import sys
import os

class Vulnerd:
    def __init__(self):
        self.file_name = sys.argv[1]
        self.start()

    def start(self):
        results = self.read_results(self.file_name)
        self.parse_results(results)

    @staticmethod
    def read_results(file):
        results = []
        with open(file, "r") as f:
            lines = f.read().splitlines()

            current_nmap = False
            current_host = False
            done_host = False
            current_string = ""
            current_vulns = []

            host = ""
            port = ""
            
            for i in lines:
                if "Nmap scan report for" in i:
                    current_nmap = True
                    if "(" and ")" in i:
                        host = i.split("(")[1].split(")")[0]
                    else:
                        host = i.split(" ")[4]

                if current_nmap:
                    if "/tcp" in i and "open" in i:
                        port = i.split("/")[0]
                        current_host = True

                    if current_host and "|" in i and "https://" in i:
                        cve = i.split("\t")
            
                        if len(cve) >= 5:
                            cve_id = cve[1]
                            risk = cve[2]
                            site = cve[3]
                            maturity = cve[4]
                            current_vulns.append([host, port, cve_id, risk, site, maturity])

                if "Nmap done" in i:
                    done_host = True

                if done_host:
                    if len(current_vulns) > 0:
                        results.append({host: current_vulns})
                        #print(results)
                    host = ""
                    current_vulns = []
                    done_host = False
                    current_nmap = False
                    current_host = False
        return results


    def parse_results(self, results_blob):
        # Create a new file based on the text document, and output as .tsv
        new_file_name = os.path.splittext(self.file_name)[0] + ".tsv"
        with open(new_file_name, "w") as w:
            for item in results_blob:
                for key, val in item.items():
                    host = key
                    for i in val:
                        port = i[1]
                        #print(f"Port: {port}")
                        cve_id = i[2]
                        cve_risk = float(i[3])
                        cve_link = i[4]
                        maturity = i[5]
                        if cve_risk >= 4.5:
                            w.write("\t".join([host, port, cve_id, str(cve_risk), maturity, cve_link]) + "\n")
        print(f"Done! Results saved to {new_file_name}.")


if __name__ == "__main__":
    v = Vulnerd()
