### VULNSCAN suite
# vulngen
#
# Run anchore/grype utility to detect vulnerabilities on previously generated SBOMs
# Results are stored back in database as json field
#
import psycopg
from datetime import datetime
from psycopg.rows import dict_row
import os, sys, json, tempfile, subprocess
from psycopg.types.json import Json


def loop_db():
    print("Generating vulnerability data for containers...",flush=True)
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        if refresh_all:
            print("Refreshing data on ALL containers", flush=True)
            cur.execute("SELECT id, namespace, container, image, image_id, sbom FROM containers;")
        else:
            print("Refreshing data on running containers without vulnerability data", flush=True)
            cur.execute("SELECT id, namespace, container, image, image_id, sbom FROM containers WHERE k8s_running AND NOT vulnscan_generated;")
        curupdate = conn.cursor()
        for row in cur:
            print(row["image"]+" needs vulnerability scan generated... creating")
            sbomfile=tempfile.NamedTemporaryFile(mode='w',delete=False)
            json.dump(row["sbom"],sbomfile)
            sbomfilename=sbomfile.name
            sbomfile.close()
            cmdtoexec = ['grype', 'sbom:' + sbomfilename,'-o','json']
            vulngenfile = subprocess.run(cmdtoexec, capture_output=True)
            vulngenjsontxt = vulngenfile.stdout.decode()
            if vulngenfile.returncode != 0:
                print("Error executing grype command, error code: "+str(vulngenfile.returncode),flush=True)
            if len(vulngenjsontxt) > 0:
                vulngenjson=json.loads(vulngenjsontxt)
                print("Scan on " + row["image"] + " completed. Uploading to DB...")
                curupdate.execute("UPDATE containers SET vulnscan=%s,vulnscan_generated=%s,vulnscan_gen_date=%s WHERE id=%s;", \
                    (Json(vulngenjson),True,datetime.now(),row["id"]))
                conn.commit()
        print("Generating Materialized view for vulnerabilities...", flush=True)
        cur.execute("REFRESH MATERIALIZED VIEW container_vulnerabilities;")
        print("Materialized view for vulnerabilities created.", flush=True)

# main

db_host=os.environ.get('DB_HOST')
db_name=os.environ.get('DB_NAME')
db_user=os.environ.get('DB_USER')
db_password=os.environ.get('DB_PASSWORD')
refresh_all_txt=os.environ.get('REFRESH_ALL')
refresh_all=(refresh_all_txt.upper() in ['1',"TRUE","YES"])

pdsn="host=" + db_host + ' dbname=' + db_name + " user=" + db_user + " password=" + db_password

loop_db()
sys.exit(0)
