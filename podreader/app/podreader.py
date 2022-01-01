# VULNSCAN SUITE
# podreader
#
# Compares active pods/images against database and adds new ones in
# Optionally expires old pods no longer running
#
from kubernetes import client, config, watch
import psycopg
from datetime import datetime, timedelta
from psycopg.rows import dict_row
import sys, os

def check_create_table():
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor()
        cur.execute("select * from information_schema.tables where table_name=%s",('images',))
        tbl_exists=bool(cur.rowcount)
        if not tbl_exists:
            print("Initial run, images table did not exist, creating", flush=True)
            cur.execute("""
                CREATE TABLE images (
                    id serial PRIMARY KEY,
                    image text NOT NULL,
                    image_id_digest text,
                    image_running boolean not null,
                    last_image_scan_date timestamptz NULL,
                    sbom_generated boolean not null,
                    sbom_gen_date timestamp with time zone,
                    sbom jsonb,
                    vulnscan_generated boolean not null,
                    vulnscan_gen_date timestamp with time zone,
                    vulnscan jsonb
                    )
                """)
        conn.commit()
        cur.execute("select * from information_schema.tables where table_name=%s",('containers',))
        tbl_exists=bool(cur.rowcount)
        if not tbl_exists:
            print("Initial run, containers table did not exist, creating", flush=True)
            cur.execute("""
                CREATE TABLE containers (
                    id serial PRIMARY KEY,
                    namespace text NOT NULL,
                    container text NOT NULL,
                    imageid integer,
                    pod text NOT NULL,
                    init_container boolean,
                    container_running boolean,
                    last_container_scan_date timestamptz NULL,
                    CONSTRAINT fk_containers_images
                        FOREIGN KEY(imageid)
                        REFERENCES images(id)
                    );
                """)
        conn.commit()
        cur.execute("select * from information_schema.tables where table_name=%s",('vuln_ignorelist',))
        tbl_exists=bool(cur.rowcount)
        if not tbl_exists:
            print("Initial run, ignorelist table did not exist, creating", flush=True)
            cur.execute("""
                CREATE TABLE vuln_ignorelist (
                    id serial PRIMARY KEY,
                	vuln_id text NOT NULL,
                	artifact_name text NOT NULL,
                	artifact_version text NOT NULL,
                	"namespace" text NOT NULL,
                	container text NOT NULL,
                	image text NOT NULL,
                	image_id_digest text NOT NULL
                );
                """)
        conn.commit()
        cur.execute("""
            CREATE OR REPLACE VIEW container_images
            AS
            SELECT c.id, c."namespace", c.container, c.init_container, i.image, i.image_id_digest,
                c.pod, i.image_running, i.last_image_scan_date, c.container_running, c.last_container_scan_date,
                i.sbom_generated, i.sbom_gen_date, i.sbom,
                i.vulnscan_generated, i.vulnscan_gen_date, i.vulnscan
            FROM containers c
            LEFT JOIN images i ON c.imageid = i.id;
            """)
        conn.commit()
        cur.execute("""
            create or replace view container_vulnerabilities_base
            as
            select id as container_id, namespace, container, init_container, image, image_id_digest, pod,
            image_running, last_image_scan_date, container_running, last_container_scan_date,
            sbom_generated , sbom_gen_date,
            vulnscan_generated, vulnscan_gen_date,
            m.vulnerability->>'id' as vuln_id,
            m.vulnerability->>'severity' as vuln_severity, m.artifact->>'name' as artifact_name,
            m.artifact->>'version' as artifact_version, m.vulnerability->>'description' as vuln_description,
            m.vulnerability->>'dataSource' as vuln_datasource,
            m.vulnerability->'fix'->>'state' as vuln_fix_state,
            m.vulnerability->'fix'->>'versions' as vuln_fix_versions
            from container_images
            left join lateral jsonb_to_recordset(container_images.vulnscan->'matches') as
            m(artifact json, vulnerability json ) on true
            order by namespace, container, image, image_id_digest, vuln_id, artifact_name, artifact_version;
            """)
        conn.commit()
        cur.execute("""
            create or replace view containers_no_json
            as
            select id, namespace, container, init_container, image, image_id_digest, pod,
            image_running, last_image_scan_date, container_running, last_container_scan_date,
            sbom_generated, sbom_gen_date,
            vulnscan_generated, vulnscan_gen_date
            from container_images
            order by namespace, container, image, image_id_digest;
            """)
        conn.commit()
        cur.execute("select * from pg_catalog.pg_matviews where matviewname=%s",('container_vulnerabilities',))
        tbl_exists=bool(cur.rowcount)
        if not tbl_exists:
            print("Initial run, container_vulnerabilities materialized view did not exist, creating")
            cur.execute("""
                create materialized view container_vulnerabilities
                as
                select cv.container_id, cv.namespace, cv.container, cv.init_container, cv.image, cv.image_id_digest,
                cv.pod, cv.container_running, cv.last_container_scan_date, cv.sbom_generated, cv.sbom_gen_date,
                cv.image_running, cv.last_image_scan_date,
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
                ( (cv.image_id_digest = vi.image_id_digest) or (vi.image_id_digest = '*') )
                where vi.vuln_id is null;
                """)
            conn.commit()
        cur.execute("select * from pg_catalog.pg_matviews where matviewname=%s",('container_sbom',))
        tbl_exists=bool(cur.rowcount)
        if not tbl_exists:
            print("Initial run, materialized view for container_sbom does not exist, creating")
            cur.execute("""
                CREATE MATERIALIZED VIEW container_sbom
                AS
                SELECT c.id AS container_id,
                    c.namespace,
                    c.container,
                    c.init_container,
                    c.image,
                    c.image_id_digest,
                    c.pod,
                    c.image_running,
                    c.last_image_scan_date,
                    c.container_running,
                    c.last_container_scan_date,
                    c.sbom_generated,
                    c.sbom_gen_date,
                    c.vulnscan_generated,
                    c.vulnscan_gen_date,
                    s.id as artifact_id,
                    s.name  as artifact_name,
                    s.version  as artifact_version,
                    s.type as artifact_type,
                    s.language as artifact_language,
                    s.purl as artifact_purl
                    FROM container_images c
                    LEFT JOIN LATERAL jsonb_to_recordset(c.sbom -> 'artifacts'::text) as s(id text, name text, version text, type text, language text, purl text) ON true
                    ORDER BY c.namespace, c.container, c.image, c.image_id_digest, s.name;
                """)
            conn.commit()
        cur.execute("""
            CREATE OR REPLACE FUNCTION refresh_vuln_view()
                RETURNS TRIGGER
                LANGUAGE PLPGSQL
            AS
            $$
            BEGIN
                REFRESH MATERIALIZED VIEW container_vulnerabilities ;
                RETURN NEW;
            END;
            $$;
            """)
        conn.commit()
        cur.execute("select tgname from pg_catalog.pg_trigger where NOT tgisinternal and tgname=%s",('on_ignorelist_table_update',))
        tbl_exists=bool(cur.rowcount)
        if not tbl_exists:
            print("Initial run, ignorelist trigger being created...")
            cur.execute("""
                CREATE TRIGGER on_ignorelist_table_update
                    AFTER UPDATE OR INSERT OR DELETE
                    ON vuln_ignorelist
                    FOR EACH ROW
                EXECUTE PROCEDURE refresh_vuln_view();
                """)
            conn.commit()












def check_record(p_conn, p_namespace, p_container, p_initcontainer, p_image, p_image_id_digest, p_pod):
        p_initcontainer_txt=str(p_initcontainer).upper()
        cur = p_conn.cursor(row_factory=dict_row)
        cur.execute("SELECT * from images where image = %s AND image_id_digest = %s;",(p_image,p_image_id_digest,))
        image_exists=bool(cur.rowcount)
        if not image_exists:
            print("No record for image " + p_image + "/" + p_image_id_digest + " found. Creating...",flush=True)
            cur.execute("""
                INSERT INTO images (image, image_id_digest, image_running, last_image_scan_date,
                sbom_generated, vulnscan_generated )
                VALUES (%s, %s,%s,%s,%s,%s) RETURNING id;
                """,(p_image, p_image_id_digest, True, datetime.now(), False, False))
            db_image_id=cur.fetchone()["id"]
        else:
            cur.execute("""
                SELECT id from images where image=%s AND image_id_digest=%s;
            """,(p_image,p_image_id_digest))
            db_image_id=cur.fetchone()["id"]
            cur.execute("""
                UPDATE images set image_running=%s, last_image_scan_date=%s
                WHERE id = %s;
                """,(True, datetime.now(),db_image_id))
        cur.execute("""
            SELECT * FROM containers WHERE namespace=%s AND container=%s AND init_container=%s;
            """,(p_namespace, p_container, p_initcontainer_txt))
        cont_exists=bool(cur.rowcount)
        if not cont_exists:
            print("No existing record for container " + p_container + " found... Creating...", flush=True)
            cur.execute("""
                INSERT INTO containers (namespace, container, init_container, imageid, pod,
                    container_running, last_container_scan_date )
                VALUES (%s, %s, %s, %s, %s, %s, %s);""",
                (p_namespace, p_container, p_initcontainer_txt, db_image_id, p_pod, True, datetime.now()))
        else:
            cur.execute("""
                UPDATE containers SET container_running=%s, last_container_scan_date=%s WHERE
                namespace=%s AND container=%s AND init_container=%s ;
                """,(True, datetime.now(), p_namespace, p_container, p_initcontainer_txt))

def read_pods():
    v1 = client.CoreV1Api()
    pod_list = v1.list_pod_for_all_namespaces()
    with psycopg.connect(pdsn) as conn:
        for pod in pod_list.items:
            for sta in pod.status.container_statuses:
                check_record(conn,pod.metadata.namespace, sta.name, False, sta.image, sta.image_id, pod.metadata.name)
                apprec={"namespace": pod.metadata.namespace, "container": sta.name, "init_container": False, \
                        "image": sta.image, "image_id_digest": sta.image_id, "pod": pod.metadata.name}
                pods.append(apprec)
            if not (pod.status.init_container_statuses is None):
                for sta in pod.status.init_container_statuses:
                    check_record(conn,pod.metadata.namespace, sta.name, True, sta.image, sta.image_id, pod.metadata.name)
                    apprec={"namespace": pod.metadata.namespace, "container": sta.name, "init_container": True, \
                        "image": sta.image, "image_id_digest": sta.image_id, "pod": pod.metadata.name}
                    pods.append(apprec)

def loop_psql():
    print("Checking database pods vs. active pods...",flush=True)
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("SELECT id, image, image_id_digest FROM images WHERE image_running;")
        for row in cur:
            podexists=False
            for pod in pods:
                if (pod["image_id_digest"] == row["image_id_digest"]) and (pod["image"] == row["image"]):
                    podexists=True
            if not podexists:
                print("found image " + row["image"] + "/" + row["image_id_digest"] + " in image database not currently running...",flush=True)
                curupdate = conn.cursor()
                curupdate.execute("UPDATE images SET image_running=%s WHERE id=%s;",(False, row["id"]))
        cur.execute("SELECT id, namespace, container, init_container, pod FROM containers WHERE container_running;")
        for row in cur:
            podexists=False
            for pod in pods:
                if (pod["namespace"] == row["namespace"] and pod["container"] == row["container"] \
                and pod["init_container"] == row["init_container"] ):
                    podexists=True
            if not podexists:
                print("found container "+ row["pod"] + " in namespace " + row["namespace"] + " in database not currently running...",flush=True)
                curupdate = conn.cursor()
                curupdate.execute("UPDATE containers SET container_running=%s WHERE id=%s;",(False, row["id"]))

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
        cur.execute("DELETE FROM containers WHERE (NOT container_running) AND last_container_scan_date <= %s;",(expire_compare_date,))
        print("Expired " + str(cur.rowcount) + " containers.")
        cur.execute("""
            DELETE FROM images WHERE (NOT image_running) AND (last_image_scan_date <= %s) AND (id NOT IN
                (select imageid from containers where imageid = images.id));
            """,(expire_compare_date,))
        print("Expired " + str(cur.rowcount) + " images.")

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

config.load_incluster_config()

pods = []
check_create_table()
loop_pods()
loop_psql()
expire_conts()
sys.exit(0)
