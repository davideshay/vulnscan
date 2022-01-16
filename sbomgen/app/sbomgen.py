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
        cur.execute("""
            SELECT id, image, image_id_digest
            FROM images WHERE NOT sbom_generated;
            """)
        curupdate = conn.cursor()
        for row in cur:
            print(row["image_id_digest"]+" needs SBOM generated... creating")
            cmdtoexec = ['syft', '-q', row["image_id_digest"], '-o', 'json']
            sbomfile = subprocess.run(cmdtoexec, capture_output=True)
            sbomjsontxt = sbomfile.stdout.decode()
            if sbomfile.returncode != 0:
                print("Error occurred generating SBOM by image_id "+ row["image_id_digest"] + " ret code is " + str(sbomfile.returncode),flush=True)
                print("Trying by image name " + row["image"] + " instead of ID",flush=True)
                cmdtoexec = ['syft', '-q', row["image"], '-o', 'json']
                sbomfile2 = subprocess.run(cmdtoexec, capture_output=True)
                sbomjsontxt = sbomfile2.stdout.decode()
                if sbomfile2.returncode != 0:
                    print("SBOM generation still failed by image ret code is " + str(sbomfile2.returncode),flush=True)
            if len(sbomjsontxt) > 0:
                sbomjson = json.loads(sbomjsontxt)
                print("Generated a complete SBOM for image " + row["image"] + " ... about to load ...",flush=True)
                curupdate.execute("UPDATE images SET sbom=%s,sbom_generated=%s,sbom_gen_date=%s WHERE id=%s;",(Json(sbomjson),True,sbomgen_run_date,row["id"]))
                conn.commit()
            else:
                print("ERROR: No SBOM image generated for image " + row["image"],flush=True)
        print("Regenerating materialized SBOM view...", flush=True)
        cur.execute("REFRESH MATERIALIZED VIEW container_sbom;")
        print("SBOM view materialized.", flush=True)

def update_run_date():
    with psycopg.connect(pdsn) as conn:
        cur1 = conn.cursor(row_factory=dict_row)
        cur1.execute("UPDATE sysprefs SET last_sbomgen_run_date = %s WHERE userid = %s",(sbomgen_run_date,'system'))

# main
db_host=os.environ.get('DB_HOST')
db_name=os.environ.get('DB_NAME')
db_user=os.environ.get('DB_USER')
db_password=os.environ.get('DB_PASSWORD')

pdsn="host=" + db_host + ' dbname=' + db_name + " user=" + db_user + " password=" + db_password

sbomgen_run_date=datetime.now()

loop_db()
update_run_date()
sys.exit(0)
