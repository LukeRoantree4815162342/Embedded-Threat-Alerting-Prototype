from email import message_from_file, message, generator
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import argparse
import scan_csv
from base64 import b64decode, b64encode
import os
from io import StringIO
from gooey import Gooey, GooeyParser


cwd = os.getcwd()

@Gooey(program_name='Embedded Threat Alerting', image_dir='./images')
def main():
    outfile_name = 'QuarterlyReportEmail.eml'

    #----- CLI parsing section <start>-----------------------------
    parser = GooeyParser(description="ETA Prototype")
    parser.add_argument('eml', type=str, widget='FileChooser', help='The eml to scan')
    args = parser.parse_args()
    #----- CLI parsing section <end>-------------------------------

    #----- CSV extraction section <start>--------------------------
    with open(args.eml, 'r') as f:
        mess = message_from_file(f)
    payloads = mess.get_payload()
    payload_types = [p.get_content_type() for p in payloads]

    csv_payloads_indexes = [i for i in range(len(payloads)) if payload_types[i]=='text/csv']
    csv_attachments_as_strings = [payloads[i].get_payload(decode=True).decode('UTF-8') for i in csv_payloads_indexes]
    #----- CSV extraction section <end>----------------------------

    #----- CSV processing section <start>--------------------------
    reports = []
    safe_csvs = []
    for index,attachment in enumerate(csv_attachments_as_strings):
        formulae_occurances = scan_csv.detect_formulae(attachment) # TODO: find how to auto-detect delimiter
        malicious_cells = scan_csv.detect_malicious_cells(formulae_occurances)
        report = scan_csv.generate_report(formulae_occurances, malicious_cells)
        safe_csv = scan_csv.generate_protected_csv(attachment, malicious_cells)
        if report is not None:
            reports.append("ProofPoint has noticed that attachment {} is suspicious:\r\n{}".format(payloads[index].get_filename(), report))
        if len(formulae_occurances) > 0:
            safe_csvs.append(safe_csv)
    #----- CSV processing section <end>----------------------------

    #----- Reports + safe CSV into email section <start>-----------
    with open(args.eml, 'r') as f:
        mess = message_from_file(f)

    for index, report in enumerate(reports):
        tempfile_report = StringIO(report)
        tempfile_csv = StringIO(safe_csvs[index])
        report_message = MIMEApplication(tempfile_report.read(), Name='ProofPoint_Warning_{}.txt'.format(index+1))
        report_message['Content-Disposition'] = 'attachment; filename="ProofPoint_Warning_{}.txt"'.format(index+1)
        safe_csv = MIMEApplication(tempfile_csv.read(), Name='ProofPoint_Secured_{}.csv'.format(index+1))
        safe_csv['Content-Disposition'] = 'attachment; filename="ProofPoint_Secured_{}.csv"'.format(index+1)
        mess.attach(report_message)
        mess.attach(safe_csv)

    if len(reports) > 0:
        warning = MIMEText(StringIO('<H2 style="color:red">ProofPoint has detected potential threats in an attachment to this email,<br/> see the ProofPoint_Warning attachments for more details</H2>').read())
        warning.set_default_type('text/html')
        mess.attach(warning)

    with open(outfile_name, 'w') as outfile:
            gen = generator.Generator(outfile)
            gen.flatten(mess)
    #----- Reports + safe CSV into email section <end>-------------

if __name__=='__main__':
    main()
