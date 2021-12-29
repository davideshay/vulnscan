from kubernetes import client, config, watch
import psycopg
from datetime import datetime, timedelta
from psycopg.rows import dict_row
import sys, os

def check_create_table():
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor()
        cur.execute("select * from information_schema.tables where table_name=%s",('containers',))
        tbl_exists=bool(cur.rowcount)
        if not tbl_exists:
            print("Initial run, containers table did not exist, creating", flush=True)
            cur.execute("""
                CREATE TABLE containers (
                    id serial PRIMARY KEY,
                    namespace text,
                    container text,
                    image text,
                    image_id text,
                    pod text,
                    k8s_running boolean not null,
                    last_pod_scan_date timestamp with time zone,
                    sbom_generated boolean not null,
                    sbom_gen_date timestamp with time zone,
                    sbom jsonb,
                    vulnscan_generated boolean not null,
                    vulnscan_gen_date timestamp with time zone,
                    vulnscan jsonb
                    )
                """)
        cur.execute("""
            create or replace view container_vulnerabilities_base
            as
            select id as container_id, namespace, container, image, image_id, pod, k8s_running,
            last_pod_scan_date, sbom_generated , sbom_gen_date,
            vulnscan_generated, vulnscan_gen_date,
            m.vulnerability->>'id' as vuln_id,
            m.vulnerability->>'severity' as vuln_severity, m.artifact->>'name' as artifact_name,
            m.artifact->>'version' as artifact_version, m.vulnerability->>'description' as vuln_description,
            m.vulnerability->>'dataSource' as vuln_datasource,
            m.vulnerability->'fix'->>'state' as vuln_fix_state,
            m.vulnerability->'fix'->>'versions' as vuln_fix_versions
            from containers
            left join lateral jsonb_to_recordset(containers.vulnscan->'matches') as
            m(artifact json, vulnerability json ) on true
            order by namespace, container, image, image_id, vuln_id, artifact_name, artifact_version;
            """)
        cur.execute("""
            create or replace view containers_no_json
            as
            select id, namespace, container, image, image_id, pod,
            k8s_running, last_pod_scan_date, sbom_generated, sbom_gen_date,
            vulnscan_generated, vulnscan_gen_date
            from containers
            order by namespace, container, image, image_id;
            """)
        cur.execute("select * from pg_catalog.pg_matviews where matviewname=%s",('container_vulnerabilities',))
        tbl_exists=bool(cur.rowcount)
        if not tbl_exists:
            cur.execute("""
                create materialized view container_vulnerabilities
                as
                select cv.container_id, cv.namespace, cv.container, cv.image, cv.image_id,
                cv.pod, cv.k8s_running, cv.last_pod_scan_date, cv.sbom_generated, cv.sbom_gen_date,
                cv.vulnscan_generated, cv.vulnscan_gen_date,
                cv.vuln_id, cv.vuln_severity, cv.artifact_name, cv.artifact_version,
                cv.vuln_description, cv.vuln_datasource, cv.vuln_fix_state, cv.vuln_fix_versions
                from container_vulnerabilities_base cv
                left join vuln_ignorelist vi
                on
                ( (cv.vuln_id = vi.vuln_id) or (vi.vuln_id = '*') )
                and
                ( (cv.artifact_name = vi.artifact_name) or (vi.artifact_name = '*') )
                and
                ( (cv.artifact_version = vi.artifact_version) or (vi.artifact_version = '*') )
                and
                ( (cv."namespace" = vi."namespace") or (vi."namespace" = '*') )
                and
                ( (cv.container = vi.container) or (vi.container = '*') )
                and
                ( (cv.image = vi.image) or (vi.image = '*') )
                and
                ( (cv.image_id = vi.image_id) or (vi.image_id = '*') )
                where vi.vuln_id is null;
                """)
        cur.execute("select * from pg_catalog.pg_matviews where matviewname=%s",('container_sbom',))
        tbl_exists=bool(cur.rowcount)
        if not tbl_exists:
            cur.execute("""
                CREATE MATERIALIZED VIEW container_sbom
                AS
                SELECT containers.id AS container_id,
                    containers.namespace,
                    containers.container,
                    containers.image,
                    containers.image_id,
                    containers.pod,
                    containers.k8s_running,
                    containers.last_pod_scan_date,
                    containers.sbom_generated,
                    containers.sbom_gen_date,
                    containers.vulnscan_generated,
                    containers.vulnscan_gen_date,
                    s.id as artifact_id,
                    s.name  as artifact_name,
                    s.version  as artifact_version,
                    s.type as artifact_type,
                    s.language as artifact_language,
                    s.purl as artifact_purl
                    FROM containers
                    LEFT JOIN LATERAL jsonb_to_recordset(containers.sbom -> 'artifacts'::text) as s(id text, name text, version text, type text, language text, purl text) ON true
                    ORDER BY containers.namespace, containers.container, containers.image, containers.image_id, s.name;
                """)

def check_record(p_conn, p_namespace, p_container, p_image, p_image_id, p_pod):
#    print("checking mongo for namespace " + p_namespace + " container "+ p_container + " image " + p_image + " id " + p_imageid + " pod " + p_pod,flush=True)
        cur = p_conn.cursor()
        cur.execute("""
            SELECT * FROM containers WHERE namespace=%s AND container=%s AND image=%s AND image_id=%s;
            """,(p_namespace, p_container, p_image, p_image_id))
        cont_exists=bool(cur.rowcount)
        curupdate = p_conn.cursor()
        if not cont_exists:
            print("No existing record for image " + p_image + " found... Creating...", flush=True)
            curupdate.execute("""
                INSERT INTO containers (namespace, container, image, image_id,
                    pod, k8s_running, last_pod_scan_date, sbom_generated, vulnscan_generated)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);""",
                (p_namespace, p_container, p_image, p_image_id, p_pod, True, datetime.now(), False, False))
        else:
            curupdate.execute("""
                UPDATE containers SET last_pod_scan_date=%s, k8s_running=%s WHERE
                namespace=%s AND container=%s AND image=%s AND image_id=%s;
                """,(datetime.now(), True, p_namespace, p_container, p_image, p_image_id))

def read_pods():
    v1 = client.CoreV1Api()
#    print("v1 client created", flush=True)
    pod_list = v1.list_pod_for_all_namespaces()
    with psycopg.connect(pdsn) as conn:
        for pod in pod_list.items:
            for sta in pod.status.container_statuses:
                check_record(conn,pod.metadata.namespace, sta.name, sta.image, sta.image_id, pod.metadata.name)
                apprec={"namespace": pod.metadata.namespace, "container": sta.name,
                        "image": sta.image, "image_id": sta.image_id, "pod": pod.metadata.name}
                pods.append(apprec)

def loop_psql():
    print("Looping through database...",flush=True)
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("SELECT id, namespace, container, pod, image, image_id FROM containers WHERE k8s_running;")
        for row in cur:
            podexists=False
            for pod in pods:
                if (pod["namespace"] == row["namespace"] and pod["container"] == row["container"] \
                and pod["image"] == row["image"] and pod["image_id"] == row["image_id"]):
                    podexists=True
            if not podexists:
                print("found pod "+ row["pod"] + " in namespace " + row["namespace"] + " in database not currently running...",flush=True)
                curupdate = conn.cursor()
                curupdate.execute("UPDATE containers SET k8s_running=%s WHERE id=%s;",(False, row["id"]))

def loop_pods():
    try:
        read_pods()
    except Exception as e:
        print(str({"level": "error", "message": str(e), "traceback": traceback.format_exc()}))
        loop_pods()

def expire_conts():
    if expire_containers:
        print("Expiring pods older than " + str(expire_days) + " days...")
    else:
        print("Expire pods not enabled, skipping expiration")
        return
    expire_days_delta = timedelta(days=expire_days)
    expire_compare_date = datetime.now() - expire_days_delta
    print("Expiring container records last scanned before " + str(expire_compare_date))
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("DELETE FROM containers WHERE (NOT k8s_running) AND last_pod_scan_date <= %s;",(expire_compare_date,))
        print("Expired " + str(cur.rowcount) + " containers.")

# main

db_host=os.environ.get('DB_HOST')
db_name=os.environ.get('DB_NAME')
db_user=os.environ.get('DB_USER')
db_password=os.environ.get('DB_PASSWORD')
expire_containers_txt=os.environ.get('EXPIRE_CONTAINERS')
expire_containers=(expire_containers_txt.upper() in ['1','YES','TRUE'])
expire_days_txt=os.environ.get('EXPIRE_DAYS')
if expire_days_txt.isnumeric():
    expire_days=int(expire_days_txt)
else:
    expire_days=5

pdsn="host=" + db_host + ' dbname=' + db_name + " user=" + db_user + " password=" + db_password

print("In main, about to load cluster config", flush=True)
config.load_incluster_config()

pods = []
print("Loaded cluster config, about to loop pods", flush=True)
check_create_table()
loop_pods()
loop_psql()
expire_conts()
sys.exit(0)
