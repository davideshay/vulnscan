import psycopg
from datetime import datetime
from psycopg.rows import dict_row
import sys, os, json
from http.server import BaseHTTPRequestHandler, HTTPServer
from os import curdir, sep
import flask
from flask import render_template, Flask, request, redirect

app = Flask(__name__, static_folder="static")


def get_vulnerabilities():
    vulns=[]
    print("Looping through database...",flush=True)
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT container_id,namespace, container, image, image_id, artifact_name, artifact_version, vuln_id, vuln_severity,
            vuln_datasource, vuln_fix_state, vuln_fix_versions
            FROM container_vulnerabilities;
            """)
        for row in cur:
            vulns.append(row)
    return vulns

def get_vulnerability_json(container_id):
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT namespace, container, image, vulnscan, vulnscan_gen_date
            FROM containers
            WHERE id=%s ;
            """,(container_id,))
        return cur.fetchone()

def get_container_vulnerabilities(container_id):
    vulns=[]
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT artifact_name, artifact_version, vuln_id, vuln_severity, 
            vuln_datasource, vuln_fix_state, vuln_fix_versions
            FROM container_vulnerabilities
            WHERE container_id=%s ;
            """,(container_id,))
        for row in cur:
            vulns.append(row)
    return vulns

def get_sboms():
    sboms=[]
    print("Looping through database...",flush=True)
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT container_id,namespace, container, image, image_id, artifact_id, artifact_name, artifact_version,
            artifact_type, artifact_language, artifact_purl
            FROM container_sbom;
            """)
        for row in cur:
            sboms.append(row)
    return sboms

def get_sbom_json(container_id):
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT namespace, container, image, sbom, sbom_gen_date
            FROM containers
            WHERE id=%s ;
            """,(container_id,))
        return cur.fetchone()

def get_container_sboms(container_id):
    sboms=[]
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT artifact_id, artifact_name, artifact_version, artifact_type,
            artifact_language, artifact_purl
            FROM container_sbom
            WHERE container_id=%s ;
            """,(container_id,))
        for row in cur:
            sboms.append(row)
    return sboms

def get_containers():
    containers=[]
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT id, namespace, container, image, image_id, pod, k8s_running, last_pod_scan_date,
            sbom_generated, sbom_gen_date, vulnscan_generated, vulnscan_gen_date
            FROM containers;
            """)
        for row in cur:
            containers.append(row)
    return containers

def get_container(container_id):
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT id, namespace, container, image, image_id, pod, k8s_running, last_pod_scan_date,
            sbom_generated, sbom_gen_date, sbom, vulnscan_generated, vulnscan_gen_date, vulnscan
            FROM containers
            WHERE id = %s;
            """,(container_id,))
        for row in cur:
            return row

@app.route('/api/vulnerabilities',methods=['GET'])
def api_vulnerabilities():
    data={"data": get_vulnerabilities()}
    return data

@app.route('/api/container_vulnerabilities', methods=['GET'])
def api_container_vulnerabilities():
    container_id_str=request.args.get('id',None)
    if container_id_str.isnumeric():
        data=get_container_vulnerabilities(int(container_id_str))
    else:
        data={}
    rdata={"data": data}
    return rdata

@app.route('/api/sboms', methods=['GET'])
def api_sboms():
    data={"data": get_sboms()}
    return data

@app.route('/api/container_sboms', methods=['GET'])
def api_container_sboms():
    container_id_str=request.args.get('id',None)
    if container_id_str.isnumeric():
        data=get_container_sboms(int(container_id_str))
    else:
        data={}
    rdata={"data": data}
    return rdata

@app.route('/api/containers', methods=['GET'])
def api_containers():
    data={"data": get_containers()}
    return data

@app.route('/api/container', methods=['GET'])
def api_container():
    container_id_str=request.args.get('id',None)
    if container_id_str.isnumeric():
        data=get_container(int(container_id_str))
    else:
        data={}
    return data

@app.route('/vulnerabilities', methods=['GET'])
def app_vulnerabiliites():
    return render_template('vulnerabilities.html',APP_URL=APP_URL)

@app.route('/vulnerability', methods=['GET'])
def app_vulnerability():
    container_id_str=request.args.get('id',None)
    if container_id_str.isnumeric():
        data=get_vulnerability_json(int(container_id_str))
    else:
        data={}
    return render_template('vulnerability.html', data=data)

@app.route('/containers', methods=['GET'])
def app_containers():
    return render_template('containers.html', APP_URL=APP_URL)

@app.route('/container', methods=['GET'])
def app_container():
    container_id=request.args.get('id',None)
    return render_template('container.html',APP_URL=APP_URL, container_id=container_id)

@app.route('/sboms', methods=['GET'])
def app_sboms():
    return render_template('sboms.html',APP_URL=APP_URL)

@app.route('/sbom', methods=['GET'])
def app_sbom():
    container_id_str=request.args.get('id',None)
    if container_id_str.isnumeric():
        data=get_sbom_json(int(container_id_str))
    else:
        data={}
    return render_template('sbom.html', data=data)


@app.route('/', methods=['GET'])
def app_home():
    return redirect('/containers', code=302)

# main

db_host=os.environ.get('DB_HOST')
db_name=os.environ.get('DB_NAME')
db_user=os.environ.get('DB_USER')
db_password=os.environ.get('DB_PASSWORD')

APP_URL=os.environ.get('APP_URL')


pdsn="host=" + db_host + ' dbname=' + db_name + " user=" + db_user + " password=" + db_password

if (__name__ == '__main__'):
    app.run(host='0.0.0.0', port='80')

sys.exit(0)
# TODO : archive old records???
