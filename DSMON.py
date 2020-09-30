DSMON_FILE = open("DSMON.txt","r")
DSMON_list = DSMON_FILE.readlines()
i = 0
SPECIAL_list = []
OPERATIONS_list = []
AUDITOR_list = []
ROAUDIT_list = []


for DSMON_line in DSMON_list:
    i = i + 1
    if "S E L E C T E D     U S E R     A T T R I B U T E     R E P O R T" in DSMON_line:
        a = i + 4
        b = a + 22
        while a < b:
            #Create lists of applicable data
            DSMON_array = list(DSMON_list[a])
            RACF = DSMON_array[0:8]
            SPECIAL = DSMON_array[19:25]
            OPERATIONS = DSMON_array[30:36]
            AUDITOR = DSMON_array[42:48]
            ROADUDIT = DSMON_array[53:59]
            #Make them strings
            RACFs = ''.join(RACF)            
            SPECs = ''.join(SPECIAL)
            OPs = ''.join(OPERATIONS)
            AUDs = ''.join(AUDITOR)
            ROAs = ''.join(ROADUDIT)
            #Build new lists
            if "S" in SPECs or "G" in SPECs:
                SPECs_line = RACFs + " " + SPECs.rstrip("\n")
                SPECIAL_list.append(SPECs_line)

            if "S" in OPs or "G" in OPs:
                OPs_line = RACFs + " " + OPs.rstrip("\n")
                print(OPs_line)
                OPERATIONS_list.append(OPs_line)           
            
            if "S" in AUDs or "G" in AUDs:
                AUDs_line = RACFs + " " + AUDs.rstrip("\n")
                AUDITOR_list.append(AUDs_line)

            if "S" in ROAs or "G" in ROAs:
                ROAs_line = RACFs + " " + ROAs.rstrip("\n")
                ROAUDIT_list.append(ROAs_line)    
            
            a = a + 1

#Make nice Report
print("SPECIAL ACCESS")
print("##############################")
print("RACF\t Access Level")
print("\n".join(SPECIAL_list))
print("##############################")
print("OPERATIONS ACCESS")
print("##############################")
print("RACF\t Access Level")
print("\n".join(OPERATIONS_list))
print("##############################")
print("AUDITOR ACCESS")
print("##############################")
print("RACF\t Access Level")
print("\n".join(AUDITOR_list))
print("##############################")
print("ROAUDIT ACCESS")
print("##############################")
print("RACF\t Access Level")
print("\n".join(ROAUDIT_list))

