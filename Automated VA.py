import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages

va_file ='Book1.xlsx'
severity = []
DataFrame=pd.read_excel(va_file, sheet_name='Sheet1')

cvss_score=DataFrame['CVSS Score']
severity =[]
customsort=['Low' ,'Medium' , 'High', 'Critical']
for score in cvss_score:
    if score >0 and score < 4:
       severity.append('Low')
    elif score >= 4 and score < 7:
        severity.append('Medium')
    elif score >= 7 and score < 9:
        severity.append('High')
    elif score >= 9 and score <=10: 
        severity.append('Critical')


DataFrame['Severity']=severity
newdataframe=DataFrame

newdataframe['Severity'] = pd.Categorical(newdataframe['Severity'],categories=customsort)

newdataframe.to_excel('CoreTeamRepots.xlsx')

DataFrame.groupby(['Severity']).count().plot(kind='pie', y='CVSS Score',autopct='%.1f',figsize=(5, 5) ) 

CountOfDifferentVinSingleIP=pd.pivot_table(newdataframe,index=' IP Address' , columns='Severity' ,  values='CVSS Score', aggfunc='count')

Vulnerabilities_Count_By_Description=pd.pivot_table(newdataframe, index='Asset Names' , values='Vulnerability Title', aggfunc='count')
CountOfDifferentVinSingleIP.to_excel('SeverityIPCount.xlsx')

plt.savefig('PieChartVulnerability.pdf')



