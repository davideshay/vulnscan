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
import apprise
from urllib import parse

class msg_lvl(IntEnum):
    debug = 1
    info = 2
    warning = 3
    error = 4

def log_msg(lvl, message):
    if lvl >= min_log_lvl:
        print(f"level={lvl.name} ts={datetime.datetime.now()} msg={message}",flush=True)

def get_sysprefs():
    global match_image_without_tags
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute(""" SELECT userid, schema_ver, match_image_without_tags FROM sysprefs
            WHERE userid=%s;""",('system',))
        match_image_without_tags=False;
        if bool(cur.rowcount):
            sysprefs_row=cur.fetchone()
            match_image_without_tags=bool(sysprefs_row["match_image_without_tags"])
    log_msg(msg_lvl.debug,f"Match Image Without Tags: {match_image_without_tags}")

def strip_tags(imagename):
    if not match_image_without_tags:
        return imagename
    if imagename.startswith('sha256'):
        return imagename
    if ':' in imagename:
        imagename=imagename.split(':')[0]
    return imagename

def get_comparison_vulnscan(sbom_gen_date,imageid,imagename):
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        if match_image_without_tags:
            image_compare=strip_tags(imagename)
            log_msg(msg_lvl.debug,f"Checking without tags, comparing against {image_compare}")
            cur.execute("""
                    SELECT id,image,compare_image,vulnscan,sbom_gen_date
                    FROM (
                    SELECT id,image,
                    	CASE WHEN left(image,7) = 'sha256:' THEN image
                    	     ELSE left(image,strpos(image,':')-1)
                    	END AS compare_image,
                        vulnscan,sbom_gen_date
                    from images
                    ) i
                    WHERE compare_image=%s AND vulnscan is not null AND
                        sbom_gen_date <= %s
                    ORDER BY sbom_gen_date desc;
                    """,(image_compare,sbom_gen_date))
        else:
            log_msg(msg_lvl.debug,f"Checking with tags, comparing against {imagename}")
            cur.execute(""" SELECT id, image, image as compare_image, vulnscan,
                sbom_gen_date
                FROM images
                WHERE image=%s AND vulnscan is not null AND sbom_gen_date <= %s
                ORDER BY sbom_gen_date desc; """,(imagename,sbom_gen_date))
        compare_read=cur.fetchone()
        old_similar_exists=bool(cur.rowcount)
        if old_similar_exists:
            if compare_read["id"] == imageid:
                log_msg(msg_lvl.info,f"Closest similar image to {imagename} was itself with id {imageid} and name {compare_read['image']}")
            else:
                log_msg(msg_lvl.info,f"Comparing image {imagename} with unique id {imageid} to similar image unique ID {compare_read['id']} and name {compare_read['image']} ")
            compare_vulnscan=compare_read["vulnscan"]
        else:
            log_msg(msg_lvl.info,f"No similar image found. Comparing to self with unique ID {imageid}")
            cur.execute(""" SELECT id, vulnscan FROM images
                WHERE id=%s""",(imageid,))
            compare_read=cur.fetchone()
            compare_vulnscan=compare_read["vulnscan"]
    return compare_vulnscan

def generate_lookup_similar_dict(compare_vulnscan):
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
    return lookup_dict

def check_and_update_vulns(sbom,sbom_gen_date,imageid,imagename,image_id_digest):
    log_msg(msg_lvl.info,f"Assessing vuln data for {imagename} with database id {imageid}")
    compare_vulnscan=get_comparison_vulnscan(sbom_gen_date,imageid,imagename)
    lookup_similar_dict=generate_lookup_similar_dict(compare_vulnscan)
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
        lookup_cur_dict={}
        for match in vulngenjson["matches"]:
            log_msg(msg_lvl.debug,f"Checking match of {match['vulnerability']['id']} in {match['artifact']['name']}")
            lookup_key=(match["vulnerability"]["id"], match["vulnerability"]["severity"], \
                match["vulnerability"]["dataSource"], match["artifact"]["name"], \
                match["artifact"]["version"])
            if lookup_key in lookup_similar_dict:
                log_msg(msg_lvl.debug,f"Found match in similar value lookup, copying old date of {lookup_similar_dict[lookup_key]} to new json")
                match[date_key_name]=lookup_similar_dict[lookup_key]
            else:
                log_msg(msg_lvl.debug,f"No match found, using new run date of {run_vulngen_date}")
                match[date_key_name]=run_vulngen_date
            lookup_cur_dict[lookup_key]=match[date_key_name]
        for similar_key in lookup_similar_dict:
            if similar_key not in lookup_cur_dict:
                log_msg(msg_lvl.debug,f"Vulnerability resolved - {similar_key[0]} {similar_key[3]}")
                vuln_resolved={ "vuln_id": similar_key[0], \
                                "vuln_severity": similar_key[1], \
                                "vuln_datasource": similar_key[2], \
                                "artifact_name": similar_key[3], \
                                "artifact_version": similar_key[4], \
                                "imageid": imageid, \
                                "image": imagename, \
                                "image_id_digest": image_id_digest
                                }
                vulns_resolved.append(vuln_resolved)
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
                SELECT id, image, image_id_digest, sbom, sbom_gen_date from images where id=%s;
                """,(imageid,))
            rowread2=curread2.fetchone()
            log_msg(msg_lvl.info,f"{rowread2['image']} with db id {rowread2['id']} needs vulnerability scan generated... creating")
            vulnjson=check_and_update_vulns(rowread2["sbom"],rowread2["sbom_gen_date"],rowread2["id"],rowread2["image"],rowread2["image_id_digest"])

            if test_mode:
                log_msg(msg_lvl.debug,"in test mode, not updating image...")
            else:
                if vulnjson is None:
                    log_msg(msg_lvl.debug,"no vulnjson returned, cannot update db")
            if ((vulnjson is not None) > 0) and (not test_mode):
                log_msg(msg_lvl.info,f"Scan on {rowread2['image']} completed. Uploading to DB...")
                curupdate.execute("UPDATE images SET vulnscan=%s,vulnscan_generated=%s,vulnscan_gen_date=%s WHERE id=%s;", \
                    (Jsonb(vulnjson),True,run_vulngen_date,imageid))
                conn.commit()

def regenerate_vulnerabilities():
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        log_msg(msg_lvl.info,"Generating Materialized view for vulnerabilities...")
        cur.execute("REFRESH MATERIALIZED VIEW container_vulnerabilities;")
        log_msg(msg_lvl.info,"Materialized view for vulnerabilities created.")

def custom_converter(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()

def update_resolved_vulns():
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        for vuln_resolved in vulns_resolved:
            if not test_mode:
                cur.execute("""
                    INSERT INTO vulns_resolved (vuln_resolved_date, vuln_id, vuln_severity,
                    vuln_datasource, artifact_name, artifact_version, imageid, image, image_id_digest)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s);
                    """,(run_vulngen_date, vuln_resolved["vuln_id"],vuln_resolved["vuln_severity"],
                        vuln_resolved["vuln_datasource"],vuln_resolved["artifact_name"],
                        vuln_resolved["artifact_version"],vuln_resolved["imageid"],
                        vuln_resolved["image"],vuln_resolved["image_id_digest"]))
        conn.commit()

def generate_run_report():
    log_msg(msg_lvl.info,"Generating vulnerability output report")
    if test_mode:
        run_date_str=str(test_date)
    else:
        run_date_str=str(run_vulngen_date)
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            select cv.vuln_severity , count(*)
            from container_vulnerabilities cv
            where cv.vuln_last_modified_date  = %s
            group by cv.vuln_severity
            """,(run_date_str,))
        vuln_summary={}
        total_vulns=0
        for row in cur:
            vuln_summary[row["vuln_severity"]] = row["count"]
            total_vulns+=row["count"]
        vuln_count_txt=f"Found {total_vulns} new vulnerabilities"
        if total_vulns>0:
            vuln_count_txt=vuln_count_txt+": "
            vuln_count_txt=vuln_count_txt+",".join([sev+" "+str(num) for sev,num in vuln_summary.items()])
        cur.execute("""
            select count(*)
            from container_vulnerabilities cv
            where cv.vuln_last_modified_date  = %s AND cv.vuln_fix_versions<>'[]'
            group by cv.vuln_severity
            """,(run_date_str,))
        vulns_fixed=0
        if bool(cur.rowcount):
            vulns_fixed=row["count"]
        vulns_fixed_txt=f"{vulns_fixed} of these vulnerabilities have published fixes."
        cur.execute("""
            select vr.vuln_severity , count(*)
            from vulns_resolved vr
            where vr.vuln_resolved_date  = %s
            group by vr.vuln_severity
            """,(run_date_str,))
        vuln_resolved_summary={}
        vulns_total_resolved=0
        for row in cur:
            vuln_resolved_summary[row["vuln_severity"]] = row["count"]
            vulns_total_resolved+=row["count"]
        vulns_resolved_txt=f"Resolved {vulns_total_resolved} vulnerabilities"
        if vulns_total_resolved>0:
            vulns_resolved_txt=vulns_resolved_txt+": "
            vulns_resolved_txt=vulns_resolved_txt+",".join([sev+" "+str(num) for sev,num in vuln_resolved_summary.items()])
    if test_mode:
        run_date_isostr=parse.quote(test_date.isoformat())
    else:
        run_date_isostr=parse.quote(run_vulngen_date.isoformat())
    vuln_link_txt=f"{app_url}/vulnerabilities/date/{run_date_isostr}"
    vulns_resolved_link_txt=f"{app_url}/vulns_resolved/date/{run_date_isostr}"

    log_msg(msg_lvl.info,vuln_count_txt)
    log_msg(msg_lvl.info,vuln_link_txt)
    log_msg(msg_lvl.info,vulns_fixed_txt)
    log_msg(msg_lvl.info,vulns_resolved_txt)
    log_msg(msg_lvl.info,vulns_resolved_link_txt)

def update_run_date():
    with psycopg.connect(pdsn) as conn:
        cur1 = conn.cursor(row_factory=dict_row)
        cur1.execute("UPDATE sysprefs SET last_vulngen_run_date = %s WHERE userid = %s",(run_vulngen_date,'system'))

# main

vulns_resolved=[]

db_host=os.environ.get('DB_HOST')
db_name=os.environ.get('DB_NAME')
db_user=os.environ.get('DB_USER')
db_password=os.environ.get('DB_PASSWORD')
refresh_all_txt=os.environ.get('REFRESH_ALL','1')
refresh_all=(refresh_all_txt.upper() in ['1','TRUE','YES'])
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
apprise_config_yaml=os.environ.get('APPRISE_CONFIG_YAML')
app_url=os.environ.get('APP_URL','http://vulnscan.local')
test_mode_txt=os.environ.get('TEST_MODE','0')
test_mode=(test_mode_txt.upper() in ['1','TRUE','YES'])
test_date_txt=os.environ.get('TEST_DATE')
if test_mode and test_date_txt is not None:
    test_date=datetime.datetime.fromisoformat(test_date_txt)

pdsn="host=" + db_host + ' dbname=' + db_name + " user=" + db_user + " password=" + db_password

run_vulngen_date=datetime.datetime.now()
date_key_name="last_modified_date"
match_image_without_tags=False

set_json_dumps(partial(json.dumps,default=custom_converter))
if test_mode:
    log_msg(msg_lvl.info,f"Executing in TEST MODE with TEST DATE {test_date}. DB will NOT be updated")
else:
    log_msg(msg_lvl.info,f"Executing in update mode with run date of {run_vulngen_date}")
get_sysprefs()
loop_db()
update_resolved_vulns()
regenerate_vulnerabilities()
generate_run_report()
update_run_date()
sys.exit(0)
