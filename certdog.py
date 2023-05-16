import subprocess
import argparse
import sys
import re
import os

# global filenames:
tmp_domains_file = "certdog_extracted_domains.txt.crtdg"
tmp_issuers_file = "certdog_extracted_issuers.txt.crtdg"
# target = "175.178.201.26:443"
# cat 200.httpx | cut -d" " -f 1 | cut -d"/" -f 3

parser = argparse.ArgumentParser(
    "certdog.py",
    formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=40),
)

parser.add_argument(
    "-f",
    "--file",
    help="httpx output file",
    dest="hxp",
    default=sys.maxsize,
    required=True,
    type=str,
)

args = parser.parse_args()

httpx_out_path = args.hxp


def runit(cmd, timeout=20) -> str:
    try:
        out = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True,
            check=True,
            timeout=timeout,
        )
        if out.returncode == 0:
            print("cmd ran successfully!")
            return out.stdout.strip()
        else:
            print("cmd did NOT rrn successfully!")
            return False

    except:
        print("Something went WRONG!")
        return False


def get_cert(addr: str) -> None:
    cmd = "echo | openssl s_client -showcerts -servername {:s}:443 -connect {:s}:443 2>/dev/null 1>certificate-tmp.pem".format(
        addr, addr
    )
    print("debug-1")
    runit(cmd, 5)
    print("debug-2")
    return


def issuer() -> str:
    cmd = 'openssl x509 -in certificate-tmp.pem -noout -issuer -nameopt lname -nameopt sep_multiline | grep commonName= | sed "s/commonName=//"'
    print("debug-3")
    issuer_name = runit(cmd)
    print("debug-4")
    return issuer_name


def dns_names() -> list:
    cmd = 'openssl x509 -noout -text -in certificate-tmp.pem | awk \'/X509v3 Subject Alternative Name/ {getline;gsub(/ /, "", $0); print}\' | sed "s/DNS://g"'
    print("debug-5")
    dns_names_lst = runit(cmd).split(",")
    print("debug-6")
    dns_names_lst = [i.strip() for i in dns_names_lst]

    cmd = 'openssl x509 -in certificate-tmp.pem -noout -subject -nameopt lname -nameopt sep_multiline | grep commonName= | sed "s/commonName=//"'
    print("debug-7")
    new_name = runit(cmd)
    print("debug-8")
    if new_name not in dns_names_lst:
        dns_names_lst.append(new_name)

    return dns_names_lst


def appendit(dns_names_lst: list, issuer: str) -> None:
    with open(tmp_domains_file, "+a") as f:
        f.write("\n".join(dns_names_lst) + "\n")

    with open(tmp_issuers_file, "+a") as f:
        f.write(issuer + "\n")

    return None


rgx = r"^(?:https?://)?([^ /\n]*)"

with open(httpx_out_path, "r") as f:
    targets = f.read()
    targets = targets.split("\n")
    for trg in targets:
        if trg:
            target = re.findall(rgx, trg)[0]
            get_cert(target)
            appendit(dns_names(), issuer())


i = 1
is_domains_file_created = False
is_issuers_file_created = False
while True:
    domains_filename = "certdog_extracted_domains_{:s}.txt".format(str(i))
    issuers_filename = "certdog_extracted_issuers_{:s}.txt".format(str(i))
    if is_domains_file_created and is_issuers_file_created:
        break
    elif not os.path.isfile(domains_filename) and not is_domains_file_created:
        runit("cat {:s} | sort -u > {:s}".format(tmp_domains_file, domains_filename))
        is_domains_file_created = True
    elif not os.path.isfile(issuers_filename) and not is_issuers_file_created:
        runit("cat {:s} | sort -u > {:s}".format(tmp_issuers_file, issuers_filename))
        is_issuers_file_created = True
    else:
        i += 1


runit("rm -f certificate-tmp.pem *.crtdg")
