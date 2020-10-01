DSMON_FILE = open("DSMON.txt","r")
DSMON_list = DSMON_FILE.readlines()

num_lines = sum(1 for line in open("DSMON.txt"))

i = 0
line = 0
SPECIAL_list = []
OPERATIONS_list = []
AUDITOR_list = []
ROAUDIT_list = []
PRIV_TRUSTED_list = []
CLASS_list = []
GAT_list = []
DSET_list = []

for DSMON_line in DSMON_list:
    i = i + 1
    if "S E L E C T E D     U S E R     A T T R I B U T E     R E P O R T" in DSMON_line:
        c = i + 4
        while '1RACF DATA SECURITY MONITOR' not in DSMON_list[c]:
            #Create lists of applicable data
            DSMON_array = list(DSMON_list[c])
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
                SPECs_line = RACFs + "\t" + SPECs.rstrip("\n")
                SPECIAL_list.append(SPECs_line)

            if "S" in OPs or "G" in OPs:
                OPs_line = RACFs + "\t" + OPs.rstrip("\n")
                OPERATIONS_list.append(OPs_line)           
            
            if "S" in AUDs or "G" in AUDs:
                AUDs_line = RACFs + "\t" + AUDs.rstrip("\n")
                AUDITOR_list.append(AUDs_line)

            if "S" in ROAs or "G" in ROAs:
                ROAs_line = RACFs + "\t" + ROAs.rstrip("\n")
                ROAUDIT_list.append(ROAs_line)    
            
            #a = a + 1
            c = c + 1
    elif 'R A C F     S T A R T E D     P R O C E D U R E S     T A B L E     R E P O R T' in DSMON_line:
        c = i + 4
        while '1RACF DATA SECURITY MONITOR' not in DSMON_list[c]:
            #Create lists of applicable data
            DSMON_array = list(DSMON_list[c])
            PROF_NAME = DSMON_array[0:23]
            ASSOC_USER = DSMON_array[24:35]
            ASSOC_GROUP = DSMON_array[36:47]
            PRIV = DSMON_array[48:51]
            TRUSTED = DSMON_array[60:63]
            TRACE = DSMON_array[69:72]
            #Make them strings
            PROF_NAMEs = ''.join(PROF_NAME)            
            ASSOC_USERs = ''.join(ASSOC_USER)
            ASSOC_GROUPs = ''.join(ASSOC_GROUP)
            PRIVs = ''.join(PRIV)
            TRUSTEDs = ''.join(TRUSTED)
            TRACEs = ''.join(TRACE)
            #Build new lists
            if "YES" in PRIVs or "YES" in TRUSTEDs:
                PRIVs_TRUSTEDs_line = PROF_NAMEs + "  " + ASSOC_USERs + " \t " + ASSOC_GROUPs + "\t " + PRIVs + "\t " + TRUSTEDs
                PRIV_TRUSTED_list.append(PRIVs_TRUSTEDs_line)
     
            c = c + 1
    elif 'R A C F     C L A S S     D E S C R I P T O R     T A B L E     R E P O R T' in DSMON_line:
        c = i + 4
        while '1RACF DATA SECURITY MONITOR' not in DSMON_list[c]:
            #Create lists of applicable data
            DSMON_array = list(DSMON_list[c])
            CLASS_NAME = DSMON_array[0:9]
            CLASS_STATUS = DSMON_array[16:24]
            CLASS_AUDIT = DSMON_array[32:35]
            CLASS_UACC = DSMON_array[64:68]
            #Make them strings
            CLASS_NAMEs = ''.join(CLASS_NAME)            
            CLASS_STATUSs = ''.join(CLASS_STATUS)
            CLASS_AUDITs = ''.join(CLASS_AUDIT)
            CLASS_UACCs = ''.join(CLASS_UACC)
            #Build new lists
            if "YES" in CLASS_AUDITs and not "NONE" in CLASS_UACCs:
                CLASS_line = CLASS_NAMEs + " \t " + CLASS_STATUSs + "   \t" + CLASS_AUDITs + " \t \t " + CLASS_UACCs
                CLASS_list.append(CLASS_line)
     
            c = c + 1 
    elif 'R A C F     G L O B A L     A C C E S S     T A B L E     R E P O R T' in DSMON_line:
        c = i + 3
        
        while c <= num_lines - 1 and '1RACF DATA SECURITY MONITOR' not in DSMON_list[c]:
            #Create lists of applicable data
            DSMON_array = list(DSMON_list[c])
            GATC_NAME = DSMON_array[0:16]
            GAT_ACCESS = DSMON_array[18:24]
            GAT_ENTRY = DSMON_array[34:100]
            #Make them strings
            GATC_NAMEs = ''.join(GATC_NAME)            
            GAT_ACCESSs = ''.join(GAT_ACCESS)
            GAT_ENTRYs = ''.join(GAT_ENTRY)
            #Build new lists
            if "NONE" not in GAT_ACCESSs and "-- GLOBAL INACTIVE --" not in GAT_ENTRYs:
                GAT_line = GATC_NAMEs.rstrip("\n") + " \t " + GAT_ACCESSs.rstrip("\n") + "\t" + GAT_ENTRYs.rstrip("\n")
                GAT_list.append(GAT_line)
     
            c = c + 1
    elif 'S E L E C T E D     D A T A     S E T S' in DSMON_line:
        c = i + 3
        
        while c <= num_lines - 1 and '1RACF DATA SECURITY MONITOR' not in DSMON_list[c]:
            #Create lists of applicable data
            DSMON_array = list(DSMON_list[c])
            DSET_NAME = DSMON_array[0:30]
            DSET_INDICATED = DSMON_array[80:83]
            DSET_PROTECTED = DSMON_array[96:99]
            DSET_UACC = DSMON_array[109:115]
            #Make them strings
            DSET_NAMEs = ''.join(DSET_NAME)            
            DSET_INDICATEDs = ''.join(DSET_INDICATED)
            DSET_PROTECTEDs = ''.join(DSET_PROTECTED)
            DSET_UACCs = ''.join(DSET_UACC)
            #Build new lists
            if "YES" in DSET_INDICATEDs.rstrip() or "NO" in DSET_PROTECTEDs.rstrip() or not "NONE" in DSET_UACCs.rstrip() and DSET_NAMEs.rstrip() is not "0":
                DSET_line = DSET_NAMEs + "\t" + DSET_INDICATEDs.rstrip("\n") + "\t \t " + DSET_PROTECTEDs.rstrip("\n") + "\t \t " + DSET_UACCs.rstrip("\n")
                DSET_list.append(DSET_line)
     
            c = c + 1

#Make nice Report
z = open("DSMON_REPORT3.txt","x")
z = open("DSMON_REPORT3.txt","a")
z.write("S E L E C T E D     U S E R     A T T R I B U T E     R E P O R T")
z.write("\n##############################")
z.write("\nSPECIAL ACCESS\n")
z.write("\n##############################")
z.write("\nRACF\t \tAccess Level\n")
z.write("\n".join(SPECIAL_list))
z.write("\n##############################")
z.write("\nOPERATIONS ACCESS\n")
z.write("\n##############################")
z.write("\nRACF\t \tAccess Level\n")
z.write("\n".join(OPERATIONS_list))
z.write("\n##############################")
z.write("\nAUDITOR ACCESS\n")
z.write("\n##############################")
z.write("\nRACF\t \tAccess Level\n")
z.write("\n".join(AUDITOR_list))
z.write("\n##############################")
z.write("\nROAUDIT ACCESS\n")
z.write("\n##############################")
z.write("\nRACF\t \tAccess Level\n")
z.write("\n".join(ROAUDIT_list))
z.write('\n')
z.write("\nR A C F     S T A R T E D     P R O C E D U R E S     T A B L E     R E P O R T")
z.write("\n##############################")
z.write("\nPROF NAME\t\t ASSOC USER\t ASSOC GROUP\t PRIV\t TRUSTED\n")
z.write("\n".join(PRIV_TRUSTED_list))
z.write('\n')
z.write("\nR A C F     C L A S S     D E S C R I P T O R     T A B L E")
z.write("\n##############################")
z.write("\nCLASS NAME\t STAUS\t \tAUDITING\t UACC\n")
z.write("\n".join(CLASS_list))
z.write('\n')
z.write("\nS E L E C T E D     D A T A     S E T S")
z.write("\n##############################\n")
z.write("\nDSET NAME\t \t \tRACF INDICATED\t RACF PROTECTED\t UACC\n")
z.write("\n".join(DSET_list))
z.write('\n')
z.write("R A C F     G L O B A L     A C C E S S     T A B L E")
z.write("\n##############################\n")
z.write("\nCLASS NAME\t \t \tACCESS LEVEL\t ENTRY NAME\n")
z.write("\n".join(GAT_list))
z.write('\n')
