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

def loop_db():
    print("Generating SBOMS for containers running and not yet generated...",flush=True)
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("SELECT id, namespace, container, image, image_id FROM containers WHERE k8s_running AND NOT sbom_generated;")
        curupdate = conn.cursor()
        for row in cur:
#TODO -- perhaps instead of running directly, we should kick off a SEPARATE kubernetes job for EACH sbom that needs to be generated?
# would be much more efficient
            print(row["image"]+" needs SBOM generated... creating")
            cmdtoexec = ['syft', '-q', row["image_id"], '-o', 'json']
            sbomfile = subprocess.run(cmdtoexec, capture_output=True)
            sbomjsontxt = sbomfile.stdout.decode()
            if sbomfile.returncode != 0:
                print("Error occurred generating SBOM by image_id "+ row["image_id"] + " ret code is " + str(sbomfile.returncode),flush=True)
                print("Trying by image name " + row["image"] + " instead of ID",flush=True)
                cmdtoexec = ['syft', '-q', row["image"], '-o', 'json']
                sbomfile2 = subprocess.run(cmdtoexec, capture_output=True)
                sbomjsontxt = sbomfile2.stdout.decode()
                if sbomfile2.returncode != 0:
                    print("SBOM generation still failed by image ret code is " + str(sbomfile2.returncode),flush=True)
            if len(sbomjsontxt) > 0:
                sbomjson = json.loads(sbomjsontxt)
                print("Generated a complete SBOM for image " + row["image"] + " ... about to load ...",flush=True)
                curupdate.execute("UPDATE containers SET sbom=%s,sbom_generated=%s,sbom_gen_date=%s WHERE id=%s;",(Json(sbomjson),True,datetime.now(),row["id"]))
                conn.commit()
            else:
                print("ERROR: No SBOM image generated for image " + row["image"],flush=True)
        print("Regenerating materialized SBOM view...", flush=True)
        cur.execute("REFRESH MATERIALIZED VIEW container_sbom;")
        print("SBOM view materialized.", flush=True)

# main
db_host=os.environ.get('DB_HOST')
db_name=os.environ.get('DB_NAME')
db_user=os.environ.get('DB_USER')
db_password=os.environ.get('DB_PASSWORD')

pdsn="host=" + db_host + ' dbname=' + db_name + " user=" + db_user + " password=" + db_password

loop_db()
sys.exit(0)
