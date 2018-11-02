import pandas as pd
from io import StringIO
import re

#----- Threat detection section <start>------------------------
def detect_formulae(csv, delimiter=',',interactive_mode=False):
    """"
    argument: csv file (as string non-interactively), <optional> csv delimiter, <optional> interactive or not
    returns: list of formulae cells
    """
    if not interactive_mode:
        csv = StringIO(csv)

    df = pd.read_csv(csv, delimiter=delimiter)
    formulae_pattern = re.compile(r'^("|\'){0,1}[\+\-\=\*\/].*')

    formulae_occurances = []

    for col in df.columns:
        new_formulae_occurances = [cell for cell in df[col] if formulae_pattern.match(str(cell))]
        for nfo in new_formulae_occurances:
            formulae_occurances.append(nfo)
    return formulae_occurances

def detect_malicious_cells(formulae_cells):
    """
    argument: output from detect_formulae()
    returns: a list of formulae cells that are malicious
    """
    danger_words = ['cmd','powershell','www','http','hyperlink','shell','bash','.exe','.sh','.bat','zsh','dash','ksh']
    return [x for x in formulae_cells if any(a in str(x).lower() for a in danger_words)]
#----- Threat detection section <end>--------------------------

#----- Protected CSV generation section <start>----------------
def generate_protected_csv(csv, malicious_cells, interactive_mode=False):
    """
    arguments: (1) the original csv, (2) the output from detect_malicious_cells()
    returns: a StringIO csv object
    """
    if not interactive_mode:
        csv = StringIO(csv)
    df = pd.read_csv(csv)
    for threat in malicious_cells:
        df = df.replace(threat, "'{}".format(threat))
    return df.to_csv()

#----- Protected CSV generation section <end>------------------

#----- Reporting section <start>-------------------------------
def generate_report(formulae_occurances, malicious_cells):
    """
    arguments: (1) output from detect_formulae(), (2) output from detect_malicious_cells()
    returns: if needed, a multi-line-string report, otherwise None
    """
    if len(formulae_occurances) > 0:
        report = """There were {} formulae patterns detected.
These will be automatically evaluated by some spreadsheet editors such as Excel, this is a potential risk.
        """.format(len(formulae_occurances))

        if len(malicious_cells) > 0:
            report += """
In addition, several of these formulae cells contained keywords known to occur in malicious contexts;
please verify with the sender why the following cell formulae are required:
{}
        """.format("".join("{}\n".format(mc) for mc in malicious_cells))
        return report
    return None
#----- Reporting section <end>---------------------------------

#----- CLI parsing section <start>-----------------------------
def CLI_input():
    """
    arguments: none
    returns: tuple - csv,delimiter
    """
    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument('csv', type=str, help='The .csv to scan')
    parser.add_argument('--delimiter', '-d', type=str, help='<optional> The csv delimeter', default=',')

    args = parser.parse_args()
    return (args.csv,args.delimiter)
#----- CLI parsing section <end>-------------------------------

if __name__=='__main__':
    csv, delimiter = CLI_input()
    formulae_occurances = detect_formulae(csv, delimiter, interactive_mode=True)
    malicious_cells = detect_malicious_cells(formulae_occurances)
    print(generate_report(formulae_occurances, malicious_cells))
    
