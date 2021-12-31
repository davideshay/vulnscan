### VULNSCAN suite
# jobrunner
#
# Runs a series of jobs in the specified job directories (YAML files)
# Run sequentially by alphabetic order. Will optionally continue or fail if one job fails
#
from kubernetes import client, config, watch
import sys, os, yaml, glob

def watch_job(p_job_name,p_namespace):
    jwatch = watch.Watch()
    j_field_sel="metadata.name="+p_job_name
    w_job_complete=False
    w_job_failed=False
    w_job_succeeded=False
    batchApi=client.BatchV1Api()
    for event in jwatch.stream(func=batchApi.list_namespaced_job, namespace=p_namespace,field_selector=j_field_sel):
        if event['object'].status.conditions is not None:
            for condition in event['object'].status.conditions:
                if condition.status.upper() == "TRUE":
                    if condition.type.upper() == "COMPLETE":
                        w_job_succeeded=True
                        w_job_complete=True
                    elif condition.type.upper() == "FAILED":
                        w_job_failed=True
                        w_job_complete=True
        if w_job_complete:
            jwatch.stop()
            break
    return(w_job_succeeded)

def read_and_run_jobs():
    last_job_succeeded=True
    batchApi=client.BatchV1Api()
    filelist=glob.glob(j_dir+"/*.yaml")
    for jobfilename in sorted(filelist):
        last_job_succeeded=True
        jobfile = open(jobfilename,"r")
        jobyaml=yaml.safe_load(jobfile)
        jobfile.close()
        print("STATUS: Processing job file " + jobfilename);
        batchres = batchApi.create_namespaced_job(body=jobyaml,namespace=j_namespace)
        print("STATUS: Name of created job is " + batchres.metadata.name)
        job_succeeded=watch_job(batchres.metadata.name,j_namespace)
        if job_succeeded:
            print("STATUS: Job " + jobfilename + " Completed Successfully ")
        else:
            last_job_succeeded=False
            print("ERROR: Job " + jobfilename + " Failed, exiting...")
        if (not j_proceed_on_fail) and (not job_succeeded):
            break
    return(last_job_succeeded)

# main

j_namespace=os.environ.get('JOB_NAMESPACE')
j_dir=os.environ.get('JOB_DIR')
j_proceed_on_fail_txt=os.environ.get('JOB_PROCEED_ON_FAIL').upper()
j_proceed_on_fail = (j_proceed_on_fail_txt in ["TRUE","YES","1"])

print("Job Scheduler starting...", flush=True)
config.load_incluster_config()

final_job_success=read_and_run_jobs()
if final_job_success:
    sys.exit(0)
else:
    sys.exit(1)
