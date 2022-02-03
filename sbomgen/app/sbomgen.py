#### VULNSCAN SUITE
# sbomgen
#
# Generate SBOM using anchore/syft utility. Put back as JSON object in database
#
import psycopg
from datetime import datetime
from psycopg.rows import dict_row
import os, sys, json, subprocess
from psycopg.types.json import Json
import semver
from enum import IntEnum

class msg_lvl(IntEnum):
    debug = 1
    info = 2
    warning = 3
    error = 4

def log_msg(lvl, message):
    if lvl >= min_log_lvl:
        print(f"level={lvl.name} ts={datetime.now()} msg={message}",flush=True)

def get_syft_semver():
    cmdtoexec = ['syft', 'version', '-o', 'json']
    verfile = subprocess.run(cmdtoexec, capture_output=True)
    verfile_json_txt = verfile.stdout.decode()
    if len(verfile_json_txt) > 0:
        verfile_json=json.loads(verfile_json_txt)
        return verfile_json.get("version","")
    else:
        return ""

def loop_db():
    log_msg(msg_lvl.info,"Generating SBOMS where needed ...")
    syft_semver=get_syft_semver()
    log_msg(msg_lvl.info,f"Currently running version {syft_semver} of syft.")
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT id, image, image_id_digest, sbom #>> '{descriptor,version}' AS sbom_version, sbom_generated
            FROM images;
            """)
        curupdate = conn.cursor()
        for row in cur:
            processrow=False
            if refresh_all or (not bool(row["sbom_generated"])):
                log_msg(msg_lvl.debug,f"Image {row['image']} refreshed due to not having image or refreshing all")
                processrow=True
            else:
                if semver.compare(row["sbom_version"],syft_semver) == -1:
                    log_msg(msg_lvl.debug,f"Image {row['image']} refreshed due to semver difference on syft (image is {row['sbom_version']})")
                    processrow=True
            if not processrow:
                log_msg(msg_lvl.debug,f"Not refreshing image {row['image']}")
                continue
            log_msg(msg_lvl.info,row["image_id_digest"]+" needs SBOM generated... creating")
            cmdtoexec = ['syft', '-q', row["image_id_digest"], '-o', 'json']
            sbomfile = subprocess.run(cmdtoexec, capture_output=True)
            sbomjsontxt = sbomfile.stdout.decode()
            if sbomfile.returncode != 0:    
                log_msg(msg_lvl.debug,row)
                log_msg(msg_lvl.warning,"Error occurred generating SBOM by image_id "+ row["image_id_digest"] + " ret code is " + str(sbomfile.returncode))
                log_msg(msg_lvl.warning,"Trying by image name " + row["image"] + " instead of ID")
                cmdtoexec = ['syft', '-q', row["image"], '-o', 'json']
                sbomfile2 = subprocess.run(cmdtoexec, capture_output=True)
                sbomjsontxt = sbomfile2.stdout.decode()
                if sbomfile2.returncode != 0:
                    log_msg(msg_lvl.error,"SBOM generation still failed by image ret code is " + str(sbomfile2.returncode))
            if len(sbomjsontxt) > 0:
                sbomjson = json.loads(sbomjsontxt)
                log_msg(msg_lvl.info,"Generated a complete SBOM for image " + row["image"] + " ... about to load ...")
                curupdate.execute("UPDATE images SET sbom=%s,sbom_generated=%s,sbom_gen_date=%s WHERE id=%s;",(Json(sbomjson),True,sbomgen_run_date,row["id"]))
                conn.commit()
            else:
                log_msg(msg_lvl.error,"ERROR: No SBOM image generated for image " + row["image"])
        log_msg(msg_lvl.info,"Regenerating materialized SBOM view...")
        cur.execute("REFRESH MATERIALIZED VIEW container_sbom;")
        log_msg(msg_lvl.info,"SBOM view materialized.")

def update_run_date():
    with psycopg.connect(pdsn) as conn:
        cur1 = conn.cursor(row_factory=dict_row)
        cur1.execute("UPDATE sysprefs SET last_sbomgen_run_date = %s WHERE userid = %s",(sbomgen_run_date,'system'))

# main
db_host=os.environ.get('DB_HOST')
db_name=os.environ.get('DB_NAME')
db_user=os.environ.get('DB_USER')
db_password=os.environ.get('DB_PASSWORD')
refresh_all_txt=os.environ.get('REFRESH_ALL','FALSE')
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

pdsn="host=" + db_host + ' dbname=' + db_name + " user=" + db_user + " password=" + db_password

sbomgen_run_date=datetime.now()

loop_db()
update_run_date()
sys.exit(0)
