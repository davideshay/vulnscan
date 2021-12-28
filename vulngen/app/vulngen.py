import psycopg
from datetime import datetime
from psycopg.rows import dict_row
import os, sys, json, tempfile, subprocess
from psycopg.types.json import Json


def loop_db():
    print("Looping through database...",flush=True)
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
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



# main

db_host=os.environ.get('DB_HOST')
db_name=os.environ.get('DB_NAME')
db_user=os.environ.get('DB_USER')
db_password=os.environ.get('DB_PASSWORD')

pdsn="host=" + db_host + ' dbname=' + db_name + " user=" + db_user + " password=" + db_password

print("About to loop over containers", flush=True)
loop_db()
sys.exit(0)
