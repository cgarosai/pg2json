#!/usr/bin/env python3
import json, yaml, time, psycopg2, subprocess
from psycopg2.extras import RealDictCursor




with open("./conf.yaml") as stream:
    try:
        conf = yaml.safe_load(stream)
        conn = psycopg2.connect(
            dbname=conf["db"]["pg"]["dbName"],
            user=conf["db"]["pg"]["user"],
            password=conf["db"]["pg"]["password"],
            host=conf["db"]["pg"]["hostname"],
            port=conf["db"]["pg"]["port"]
        )
        with conn.cursor(cursor_factory=RealDictCursor) as cveCursor:
            print("--- Fetching CVEs from database ---")
            start = time.time()
            # On va récupérer la table de CVEs
            cveCursor.execute('''select
                                id,
                                name,
                                cwe,
                                modified,
                                published,
                                status,
                                summary
                            from cve
                            ORDER BY id DESC
                            ;''')
            # On itère donc sur chaque entrée de la table CVE cve
            for cve in cveCursor:
                fileName = "cves/" + cve["name"] + ".json"
                cveTosave = {
                    "id":        cve["id"],
                    "name":      cve["name"],
                    "cwe":       cve["cwe"],
                    "modified":  cve["modified"].isoformat(),
                    "published": cve["published"].isoformat(),
                    "status":    cve["status"],
                    "summary":   cve["summary"]
                }

                with conn.cursor(cursor_factory=RealDictCursor) as additionnalCursor:
                    additionnalCursor.execute('''select
                                cvss as cvss,
                                exploitability_score as exploitability_score,
                                impact_score as impact_score,
                                cvss3_vector.value as vector
                            from cvss3_mark
                            join cvss3_vector on cvss3_mark.vector_id = cvss3_vector.id
                            WHERE cve_id = %s
                            ;''' % (cveTosave["id"]))
                    cvss3 =additionnalCursor.fetchone()
                    cveTosave["cvss3"] = cvss3

                    additionnalCursor.execute('''select
                                cvss2_mark.exploitability_score exploitability_score,
                                cvss2_mark.impact_score as impact_score,
                                cvss2_mark.cvss as cvss,
                                cvss2_vector.value as vector
                            from cvss2_mark
                            join cvss2_vector on cvss2_mark.vector_id = cvss2_vector.id
                            WHERE cve_id = %s
                            ;''' % cveTosave["id"])
                    cvss2 = additionnalCursor.fetchone()
                    cveTosave["cvss2"] = cvss2
                    start = time.time_ns()
                    additionnalCursor.execute('''select
                                    cots_id as id
                                from cots_cves
                                WHERE cves_id = %s
                                ;''' % (cveTosave["id"]))
                    cpes = additionnalCursor.fetchall()
                    cveTosave["cpes"] = sorted(cpes, key=lambda d: d["id"])
                try:
                    # On créé un fichier de nom cveName.json s'il n'existe pas déjà
                    with open(fileName, 'x') as fd:
                        json.dump(cveTosave, fd, indent=4)
                # Si le fichier existe, on récupère l'objet dedans as storedCVE
                except FileExistsError:
                    with open(fileName, 'r') as fd:
                        storedCVE = json.load(fd)
                    if cveTosave != storedCVE:
                        with open(fileName, 'w') as fd:
                            json.dump(cveTosave, fd, indent=4)
                
        subprocess.run(["git", "add", "cves/*"])

        end = time.time()
        print("finished creating jsons for CVEs in %ds" % (end - start) )
        with conn.cursor(cursor_factory=RealDictCursor) as cotsCursor:
            print("--- Fetching CPEs from database ---")
            start = time.time_ns()
            cotsCursor.execute('''select * from cots ORDER BY id;''')

            for cots in cotsCursor:
                fileName = "cots/" + str(cots["id"]) + ".json"
                cotsToSave = {
                    "id":          cots["id"],
                    "name":        cots["name"],
                    "version":     cots["version"],
                    "created_at":  cots["created_at"].isoformat(),
                    "updated_at":  cots["updated_at"].isoformat(),
                    "obsolete_at": cots["obsolete_at"],
                    "cpe":         cots["cpe"],
                    "to_analyse":  cots["to_analyse"],
                }
                try:
                    # On créé un fichier de nom cveName.json s'il n'existe pas déjà
                    with open(fileName, 'x') as fd:
                        json.dump(cotsToSave, fd, indent=4)
                # Si le fichier existe, on récupère l'objet dedans as storedCVE
                except FileExistsError:
                    with open(fileName, 'r') as fd:
                        storedCots = json.load(fd)
                    if cotsToSave != storedCots:
                        with open(fileName, 'w') as fd:
                            json.dump(cotsToSave, fd, indent=4)
                
        subprocess.run(["git", "add", "cpes/*"])

        end = time.time_ns()
        print("finished creating jsons for CPEs in %ds" % ((end - start)/1000000000) )
        with conn.cursor(cursor_factory=RealDictCursor) as analysisCursor:
            print("--- Fetching CPEs from database ---")
            start = time.time_ns()
            analysisCursor.execute('''select * from applicability_analysis ORDER BY id;''')

            for analysis in analysisCursor:
                fileName = "analysis/" + str(analysis["id"]) + ".json"
                analysisToSave = {
                    "id":              analysis["id"],
                    "created_at":      analysis["created_at"].isoformat(),
                    "updated_at":      analysis["updated_at"].isoformat(),
                    "done":            analysis["done"],
                    "applicable":      analysis["applicable"],
                    "justification":   analysis["justification"],
                    "validated":       analysis["validated"],
                    "cots_id":         analysis["cots_id"],
                    "cve_id":          analysis["cve_id"],
                    "first_for_id":    analysis["first_for_id"],
                    "last_updater_id": analysis["last_updater_id"],
                    "hidden":          analysis["hidden"]
                }
                try:
                    # On créé un fichier de nom cveName.json s'il n'existe pas déjà
                    with open(fileName, 'x') as fd:
                        json.dump(analysisToSave, fd, indent=4)
                # Si le fichier existe, on récupère l'objet dedans as storedCVE
                except FileExistsError:
                    with open(fileName, 'r') as fd:
                        storedAnalysis = json.load(fd)
                    if analysisToSave != storedAnalysis:
                        with open(fileName, 'w') as fd:
                            json.dump(analysisToSave, fd, indent=4)
            subprocess.run(["git", "add", "analysis/*"])
            end = time.time_ns()
            print("finished creating jsons for Analyses in %ds" % ((end - start)/1000000000) )
        print("Conversion done, now commiting and pushing evolution")
        subprocess.run(["git", "commit", "-m", "automatic run"])
        subprocess.run(["git", "push"])

    except():
        print("Could not find configuration file, make sure you have a conf.yaml file with the right configuration")


