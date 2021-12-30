#Vulnscan Suite
Vulnscan is a suite of reporting and analysis tools built on top of anchore's syft utility (to create software bills of material) and grype utility (to scan those SBOMs for vulnerabilities).  This suite is designed to be run on a kubernetes cluster, and scan all running containers. Once scanned and the vulnerability list has been generated (and stored in a local postgres database), a web UI is available to report on your containers, SBOMs and scanned vulnerabilities.  In addition, you can create an "ignore list" at any desired level to ignore false positives from grype and/or ignore vulnerabilities which you may have resolved in other ways or aren't otherwise applicable.

##Components of Vulnscan
There are 4 main components to the suite:


1. **Podreader** -- this application scans all available pods running in the database and adds any newly discovered pods to the database to be scanned. It optionally (recommended) expires older non-running pods from the database.
2. **Sbomgen** -- this application looks for any newly available containers in the database that have not yet had a software BOM generated and generates one, storing the results in a json field in the database.
3. **Vulngen** -- this application looks for any newly available containers in the database that have an SBOM generated but have not been scanned for vulnerabilities. Results are stored in a json field in the database and available for query and display.  It optionally (recommended) can be set to always refresh the vulnerability scan, in case new vulnerabilities have been added to the database after the initial SBOM generation. 
4. **Vulnweb** -- this is the Web GUI for the application, with a backend application to serve and process requests, and the frontend files for viewing, as well as providing the "Ignore List" functionality.
5. **Jobrunner** -- this is an optional component that can be used to run any set of containers in sequence in Kubernetes. In this use case, it can be used to run Podreader, Sbomgen, and Vulngen sequentially in order, and optionally only proceed to the next component if the last one succeeds. If you elect to not use this component, you can simply schedule the components as individual Cronjobs with enough time between them to allow for normal execution speed.

##Recommended Deployment And Installation Approach

If you don't currently have **postgres** installed, follow a guide elsewhere to create a postgres environment that you can use for **Vulnscan**.  It doesn't technically have to be running in the cluster as long as your pods will have access to it.  Once installed, create a new database such as "vulnscan" and a new user , i.e. "vulnscan-admin" that has all administrative privileges to the database.  The database host, database name, user, and password are all passed to the pods as environment variables, and I would recommend you use a secret in order to load them.

The recommended deployment approach uses the **Jobrunner** component scheduled as one Cronjob, however frequently you would like (the example below uses daily).  This will run **Podreader** 
followed by **Sbomgen** followed by **Vulngen**.  Execution of these jobs will require a service account with permissions to list.watch all pods. The job runner itself also requires the ability to list/create jobs. 

Separately, run a deployment and optionally ingress (recommended) to run **vulnweb**. As this application currently stands, no in-built security mechanisms are provided, so it is recommended to do this at the ingress level or otherwise provide another security mechanism to prevent unauthorized use.

Recommended YAML for deployment:
### Basics - Namespace & ServiceAccounts/Roles

```
apiVersion: v1
kind: Namespace
metadata:
  name: vulnscan
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vulnscan-serviceaccount
  namespace: vulnscan
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: vulnscan-role
rules:
- apiGroups: ["extensions","apps","batch",""]
  resources: ["endpoints","pods","services","nodes","deployments","jobs"]
  verbs: ["get", "list", "watch", "create", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: vulnscan-role-binding
  namespace: vulnscan
subjects:
- kind: ServiceAccount
  name: vulnscan-serviceaccount
  namespace: vulnscan
roleRef:
  kind: ClusterRole
  name: vulnscan-role
  apiGroup: rbac.authorization.k8s.io
---
```

Permissions could be less if you elect to not use the jobrunner.

### Secrets

Not shown here, but recommended to use a secret for providing access to your database, encoding both the username and password. The remaining examples below assume you have created a secret called 'vulnscan-db-auth' in the vulnscan namespace.

### Job Configmap

The job runner assumes the target container has a list of job YAML files in a configurable directory, i.e. /jobs. Multiple ways of doing this, but I've elected to put these job yaml's in a configmap and then mapping them into the directory as volumes.  That approach is shown below.

```
apiVersion: v1
kind: ConfigMap
metadata:
  namespace: vulnscan
  name: vulnscan-jobs-config
  labels:
    app: vulnscan
data:
  1-podreader.yaml: |-
    apiVersion: batch/v1
    kind: Job
    metadata:
       namespace: vulnscan
       generateName: vulnscan-podreader-
       labels:
          app: vulnscan-podreader
    spec:
      ttlSecondsAfterFinished: 180
      template:
         metadata:
            labels:
               app: vulnscan-podreader
         spec:
           restartPolicy: OnFailure
           nodeSelector:
             kubernetes.io/arch: "amd64"
           serviceAccountName: vulnscan-serviceaccount
           containers:
           - name: podreader
             image: registry.shaytech.net/vulnscan-podreader:latest
             env:
             - name: DB_HOST
               value: 'postgres.postgres'
             - name: DB_NAME
               value: 'vulnscan'
             - name: DB_USER
               valueFrom:
                 secretKeyRef:
                   name: vulnscan-db-auth
                   key: DB_USER
             - name: DB_PASSWORD
               valueFrom:
                 secretKeyRef:
                   name: vulnscan-db-auth
                   key: DB_PASSWORD
             - name: EXPIRE_CONTAINERS
               value: 'true'
             - name: EXPIRE_DAYS
               value: "5"
             tty: true
             imagePullPolicy: Always
  2-sbomgen.yaml: |-
    apiVersion: batch/v1
    kind: Job
    metadata:
       namespace: vulnscan
       name: vulnscan-sbomgen
       labels:
          app: vulnscan-sbomgen
    spec:
      ttlSecondsAfterFinished: 180
      template:
         metadata:
            labels:
               app: vulnscan-sbomgen
         spec:
           restartPolicy: OnFailure
           nodeSelector:
             kubernetes.io/arch: "amd64"
           serviceAccountName: vulnscan-serviceaccount
           containers:
           - name: sbomgen
             image: registry.shaytech.net/vulnscan-sbomgen:latest
             env:
             - name: DB_HOST
               value: 'postgres.postgres'
             - name: DB_NAME
               value: 'vulnscan'
             - name: DB_USER
               valueFrom:
                 secretKeyRef:
                   name: vulnscan-db-auth
                   key: DB_USER
             - name: DB_PASSWORD
               valueFrom:
                 secretKeyRef:
                   name: vulnscan-db-auth
                   key: DB_PASSWORD
             tty: true
             imagePullPolicy: Always
             resources:
               requests:
                 memory: 12Gi
               limits:
                 memory: 16Gi
  3-vulngen.yaml: |-
    apiVersion: batch/v1
    kind: Job
    metadata:
       namespace: vulnscan
       name: vulnscan-vulngen
       labels:
          app: vulnscan-vulngen
    spec:
      ttlSecondsAfterFinished: 180
      template:
         metadata:
            labels:
               app: vulnscan-vulngen
         spec:
           restartPolicy: OnFailure
           nodeSelector:
             kubernetes.io/arch: "amd64"
           serviceAccountName: vulnscan-serviceaccount
           containers:
           - name: vulngen
             image: registry.shaytech.net/vulnscan-vulngen:latest
             env:
             - name: DB_HOST
               value: 'postgres.postgres'
             - name: DB_NAME
               value: 'vulnscan'
             - name: DB_USER
               valueFrom:
                 secretKeyRef:
                   name: vulnscan-db-auth
                   key: DB_USER
             - name: DB_PASSWORD
               valueFrom:
                 secretKeyRef:
                   name: vulnscan-db-auth
                   key: DB_PASSWORD
             - name: REFRESH_ALL
               value: 'true'
             tty: true
             imagePullPolicy: Always
             resources:
               requests:
                 memory: 3Gi
               limits:
                 memory: 5Gi
---
```

A few comments on the batch job parameters included here:

* All of the programs (**Podreader**, **Sbomgen**, and **Vulngen**, all need the environment variables DB_HOST, DB_NAME, DB_USER, and DB_PASSWORD passed in order to access the postgres database.
* **Podreader** takes two additional parameters:
	* EXPIRE_CONTAINERS - set to "true" to have **Podreader** expire/delete containers which are not runnning after a certain number of days. Parameter defaults to true.
	* EXPIRE_DAYS - expire containers which have not been active on the cluster for the specified number of days. Five (5) is also the default.
* **Vulngen** takes one additional parameter:
	* REFRESH_ALL - set to "true" to have **Vulngen** refresh the vulnerability for all pods currently active in the cluster.  If "false", will only scan for vulnerabilities those pods which haven't yet been scanned.
* **Sbomgen** may need high memory requirements if you have very large images in your cluster. Images that are nearly 1GB may take a substantial amount of memory to generate the SBOM. I had seen nearly 10GB of memory usage at some points. You may want to set this to a lower limit and assess as needed. **Vulngen** has lower resource requirements, but can also consume significant memory when processing those same SBOMs. One of the reasons this whole process was split into 3 was to allow jobs to run at the right place, resourcewise in the cluster.
* Right now all the jobs are set to only be run on platform amd64 nodes, since I was not able to get the psycopg3 driver running on arm64. This should be able to be fixed later.
 
### JobRunner deployment

```
apiVersion: batch/v1
kind: Job
metadata:
   namespace: vulnscan
   name: vulnscan-jobrunner
   labels:
      app: vulnscan-jobrunner
spec:
  ttlSecondsAfterFinished: 180
  template:
     metadata:
        labels:
           app: vulnscan-jobrunner
     spec:
       restartPolicy: Never
       nodeSelector:
         kubernetes.io/arch: "amd64"
       volumes:
       - name: vulnscan-jobs-vol
         configMap:
           name: vulnscan-jobs-config
       serviceAccountName: vulnscan-serviceaccount
       containers:
       - name: jobrunner
         image: registry.shaytech.net/jobrunner:latest
         env:
         - name: JOB_DIR
           value: '/jobs'
         - name: JOB_NAMESPACE
           value: 'vulnscan'
         - name: JOB_PROCEED_ON_FAIL
           value: 'FALSE'
         tty: true
         imagePullPolicy: Always
         volumeMounts:
         - name: vulnscan-jobs-vol
           mountPath: "/jobs"
---
```

The **jobrunner** also takes three additional parameters:
* JOB_DIR - the jobrunner will take all .yaml files in the directory and try to create batch jobs from them.  Will be processed in alphabetical/numeric order.
* JOB_NAMESPACE - the namespace where the jobs will be created.
* JOB_PROCEED_ON_FAIL - whether to keep running the next job if the previous one fails.


### Vulnweb Deployment

```
apiVersion: apps/v1
kind: Deployment
metadata:
   namespace: vulnscan
   name: vulnscan-vulnweb
   labels:
      app: vulnscan-vulnweb
spec:
  selector:
    matchLabels:
       app: vulnscan-vulnweb
  template:
     metadata:
        labels:
           app: vulnscan-vulnweb
     spec:
       nodeSelector:
         kubernetes.io/arch: "amd64"
       serviceAccountName: vulnscan-serviceaccount
       containers:
       - name: vulnsrv
         image: registry.shaytech.net/vulnscan-vulnweb:latest
         env:
         - name: DB_HOST
           value: 'postgres.postgres'
         - name: DB_NAME
           value: 'vulnscan'
         - name: DB_USER
           valueFrom:
             secretKeyRef:
               name: vulnscan-db-auth
               key: DB_USER
         - name: DB_PASSWORD
           valueFrom:
             secretKeyRef:
               name: vulnscan-db-auth
               key: DB_PASSWORD
         ports:
         - containerPort: 80
         tty: true
         imagePullPolicy: Always
---
apiVersion: v1
kind: Service
metadata:
  name: vulnscan-vulnweb
  namespace: vulnscan
spec:
  ports:
  - port: 80
    targetPort: 80
    name: vulnscan-vulnweb
    protocol: TCP
  selector:
    app: vulnscan-vulnweb
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
   namespace: vulnscan
   name: vulnweb-ingress
   annotations:
      nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
   ingressClassName: "nginx"
   tls:
      - hosts:
        - vulnscan.example.io
   rules:
   - host: vulnscan.example.io
     http:
       paths:
          - path: /
            pathType: Prefix
            backend:
               service:
                  name: vulnscan-vulnweb
                  port:
                    number: 80

```

You can use an ingress or provide access whichever way you desire. Sample ingress configuration included above - change host name and other parameters as required, for example to add authentication.



