### VULNSCAN suite
# vulngen
#
# Run anchore/grype utility to detect vulnerabilities on previously generated SBOMs
# Results are stored back in database as json field
#
import psycopg
import datetime
from psycopg.rows import dict_row
import os, sys, json, tempfile, subprocess
from psycopg.types.json import Jsonb, set_json_dumps, set_json_loads
from functools import partial
from enum import IntEnum

class msg_lvl(IntEnum):
    debug = 1
    info = 2
    warning = 3
    error = 4

def log_msg(lvl, message):
    if lvl >= min_log_lvl:
        print(f"level={lvl.name} ts={datetime.datetime.now()} msg={message}",flush=True)

def check_and_update_vulns(sbom,sbom_gen_date,imageid,imagename):
    log_msg(msg_lvl.info,f"Assessing vuln data for {imagename} with database id {imageid}")
    compare_vulnscan={}
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute(""" SELECT id, vulnscan FROM images
            WHERE image=%s AND vulnscan is not null AND sbom_gen_date <= %s
            ORDER BY sbom_gen_date desc; """,(imagename,sbom_gen_date))
        compare_read=cur.fetchone()
        old_similar_exists=bool(cur.rowcount)
        if old_similar_exists:
            if compare_read["id"] == imageid:
                log_msg(msg_lvl.info,f"Closest similar image to {imagename} was itself with id {imageid}")
            else:
                log_msg(msg_lvl.info,f"Comparing image {imagename} with unique id {imageid} to similar image unique ID {compare_read['id']} ")
            compare_vulnscan=compare_read["vulnscan"]
        else:
            log_msg(msg_lvl.info,f"No similar image found. Comparing to self with unique ID {imageid}")
            cur.execute(""" SELECT id, vulnscan FROM images
                WHERE id=%s""",(imageid,))
            compare_read=cur.fetchone()
            compare_vulnscan=compare_read["vulnscan"]
    lookup_dict={}
    if (compare_vulnscan is not None) and ("matches" in compare_vulnscan):
        for match in compare_vulnscan["matches"]:
            if date_key_name not in match:
                log_msg(msg_lvl.debug,f"For {match['vulnerability']['id']} in {match['artifact']['name']}: No existing date key, adding current date")
                match[date_key_name]=run_vulngen_date
            lookup_key=(match["vulnerability"]["id"], match["vulnerability"]["severity"], \
                match["vulnerability"]["dataSource"], match["artifact"]["name"], \
                match["artifact"]["version"])
            lookup_dict[lookup_key]=match[date_key_name]
    sbomfile=tempfile.NamedTemporaryFile(mode='w',delete=False)
    json.dump(sbom,sbomfile)
    sbomfilename=sbomfile.name
    sbomfile.close()
    cmdtoexec = ['grype', 'sbom:' + sbomfilename,'-o','json']
    vulngenfile = subprocess.run(cmdtoexec, capture_output=True)
    vulngenjsontxt = vulngenfile.stdout.decode()
    if vulngenfile.returncode != 0:
        log_msg(msg_lvl.error,f"Error executing grype command, error code: {vulngenfile.returncode}")
    if len(vulngenjsontxt) > 0:
        vulngenjson=json.loads(vulngenjsontxt)
        for match in vulngenjson["matches"]:
            log_msg(msg_lvl.debug,f"Checking match of {match['vulnerability']['id']} in {match['artifact']['name']}")
            lookup_key=(match["vulnerability"]["id"], match["vulnerability"]["severity"], \
                match["vulnerability"]["dataSource"], match["artifact"]["name"], \
                match["artifact"]["version"])
            if lookup_key in lookup_dict:
                log_msg(msg_lvl.debug,f"Found match in similar value lookup, copying old date of {lookup_dict[lookup_key]} to new json")
                match[date_key_name]=lookup_dict[lookup_key]
            else:
                log_msg(msg_lvl.debug,f"No match found, using new run date of {run_vulngen_date}")
                match[date_key_name]=run_vulngen_date
    else:
        vulngenjson={}
    return vulngenjson

def loop_db():
    log_msg(msg_lvl.info,"Generating vulnerability data for images...")
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        if refresh_all:
            log_msg(msg_lvl.info,"Refreshing data on ALL images")
            cur.execute("SELECT id FROM images order by image, vulnscan_gen_date, sbom_gen_date;")
        else:
            log_msg(msg_lvl.info,"Refreshing data on images without vulnerability data")
            cur.execute("""
                SELECT id
                FROM images
                WHERE NOT vulnscan_generated ORDER BY image;
                """)
        curupdate = conn.cursor()
        curread2 = conn.cursor(row_factory=dict_row)
        for row in cur:
            imageid=row["id"]
            curread2.execute("""
                SELECT id, image, sbom, sbom_gen_date from images where id=%s;
                """,(imageid,))
            rowread2=curread2.fetchone()
            log_msg(msg_lvl.info,f"{rowread2['image']} with db id {rowread2['id']} needs vulnerability scan generated... creating")
            vulnjson=check_and_update_vulns(rowread2["sbom"],rowread2["sbom_gen_date"],rowread2["id"],rowread2["image"])
            if (vulnjson is not None) > 0:
                log_msg(msg_lvl.info,f"Scan on {rowread2['image']} completed. Uploading to DB...")
                curupdate.execute("UPDATE images SET vulnscan=%s,vulnscan_generated=%s,vulnscan_gen_date=%s WHERE id=%s;", \
                    (Jsonb(vulnjson),True,run_vulngen_date,imageid))
                conn.commit()
        log_msg(msg_lvl.info,"Generating Materialized view for vulnerabilities...")
        cur.execute("REFRESH MATERIALIZED VIEW container_vulnerabilities;")
        log_msg(msg_lvl.info,"Materialized view for vulnerabilities created.")

def custom_converter(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()

# main

db_host=os.environ.get('DB_HOST')
db_name=os.environ.get('DB_NAME')
db_user=os.environ.get('DB_USER')
db_password=os.environ.get('DB_PASSWORD')
refresh_all_txt=os.environ.get('REFRESH_ALL')
refresh_all=(refresh_all_txt.upper() in ['1',"TRUE","YES"])
min_log_lvl_txt=os.environ.get('MIN_LOG_LVL','I').upper()
if min_log_lvl_txt in ('I','INFO'):
    min_log_lvl=msg_lvl.info
elif min_log_lvl_txt in ('D','DEBUG'):
    min_log_lvl=msg_lvl.debug
elif min_log_lvl_txt in ('W','WARNING'):
    min_log_lvl=msg_lvl.warning
elif min_log_lvl_txt in ('E','ERROR'):
    min_log_lvl=msg_lvl.error
else:
    min_log_lvl=msg_lvl.info

pdsn="host=" + db_host + ' dbname=' + db_name + " user=" + db_user + " password=" + db_password

run_vulngen_date=datetime.datetime.now()
date_key_name="last_modified_date"

set_json_dumps(partial(json.dumps,default=custom_converter))

loop_db()
sys.exit(0)
