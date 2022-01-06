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

def check_and_update_vulns(sbom,imageid):
    compare_vulnscan={}
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute(""" SELECT id, vulnscan FROM images
            WHERE image=%s AND vulnscan_gen_date<%s AND vulnscan is not null
            ORDER BY vulnscan_gen_date desc; """,(imageid,run_vulngen_date))
        compare_read=cur.fetchone()
        old_similar_exists=bool(cur.rowcount)
        if old_similar_exists:
            compare_vulnscan=compare_read["vulnscan"]
        else:
            cur.execute(""" SELECT id, vulnscan FROM images
                WHERE id=%s""",(imageid,))
            compare_read=cur.fetchone()
            compare_vulnscan=compare_read["vulnscan"]
    lookup_dict={}
    if (compare_vulnscan is not None) and ("matches" in compare_vulnscan):
        for match in compare_vulnscan["matches"]:
            if date_key_name not in match:
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
        print("Error executing grype command, error code: "+str(vulngenfile.returncode),flush=True)
    if len(vulngenjsontxt) > 0:
        vulngenjson=json.loads(vulngenjsontxt)
        for match in vulngenjson["matches"]:
            lookup_key=(match["vulnerability"]["id"], match["vulnerability"]["severity"], \
                match["vulnerability"]["dataSource"], match["artifact"]["name"], \
                match["artifact"]["version"])
            if lookup_key in lookup_dict:
                match[date_key_name]=lookup_dict[lookup_key]
            else:
                match[date_key_name]=run_vulngen_date
    else:
        vulngenjson={}
    return vulngenjson

def loop_db():
    print("Generating vulnerability data for images...",flush=True)
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        if refresh_all:
            print("Refreshing data on ALL images", flush=True)
            cur.execute("SELECT id FROM images order by image, vulnscan_gen_date;")
        else:
            print("Refreshing data on running images without vulnerability data", flush=True)
            cur.execute("""
                SELECT id
                FROM images
                WHERE image_running AND NOT vulnscan_generated ORDER BY image;
                """)
        curupdate = conn.cursor()
        curread2 = conn.cursor(row_factory=dict_row)
        for row in cur:
            imageid=row["id"]
            curread2.execute("""
                SELECT id, image, sbom from images where id=%s;
                """,(imageid,))
            rowread2=curread2.fetchone()
            print(rowread2["image"]+" needs vulnerability scan generated... creating")
            vulnjson=check_and_update_vulns(rowread2["sbom"],rowread2["image"])
            if (vulnjson is not None) > 0:
                print("Scan on " + rowread2["image"] + " completed. Uploading to DB...")
                curupdate.execute("UPDATE images SET vulnscan=%s,vulnscan_generated=%s,vulnscan_gen_date=%s WHERE id=%s;", \
                    (Jsonb(vulnjson),True,run_vulngen_date,imageid))
                conn.commit()
        print("Generating Materialized view for vulnerabilities...", flush=True)
        cur.execute("REFRESH MATERIALIZED VIEW container_vulnerabilities;")
        print("Materialized view for vulnerabilities created.", flush=True)

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

pdsn="host=" + db_host + ' dbname=' + db_name + " user=" + db_user + " password=" + db_password

run_vulngen_date=datetime.datetime.now()
date_key_name="last_modified_date"

set_json_dumps(partial(json.dumps,default=custom_converter))

loop_db()
sys.exit(0)
