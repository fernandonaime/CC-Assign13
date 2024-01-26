#!/usr/bin/python

import subprocess
import re
import os
import stat
import time

endpath = os.getcwd() + "/report.txt"
report_file = open(endpath, 'w')
os.system('touch /etc/motd')
os.system('touch /etc/issue')
os.system('touch /etc/issue.net')


def initial_head():

    report_file.write('\n')
    report_file.write("-------------------------------------------------\n")
    report_file.write("               Intial Setup Compliance           \n")
    report_file.write("-------------------------------------------------\n")


def scan_system():

    print ("\nStarting System Scan...\n")
    report_file.write("\n================ Starting System Scan  ===============\n")

    # APT upgrade scan
    apt_log_file = '/var/log/apt/history.log'

    # Check if APT upgrade has been completed
    try:
        print ("\n=============== APT Upgrade Scan Starting ===============\n")

        with open(apt_log_file, 'r') as file:
            content = file.read()  # Corrected from file_read() to file.read()
            if 'upgrade' in content:
                print ("\nAPT upgrade activities detected in the log files.\n")
                report_file.write("\n-APT upgrade activities detected in the log files.\n")
            else:
                print ("\nNo recent APT upgrade activities detected.\n")
                report_file.write("\n-No recent APT upgrade activities detected.\n")

    except FileNotFoundError:
        print (f"\nError: Log file {apt_log_file} not found.\n")
        report_file.write(f"\n-Error: Log file {apt_log_file} not found.\n")

    print ("\n=============== APT Upgrade Scan Completed ===============\n")

    # Define the file paths
    file_path_etc_motd = '/etc/motd'
    file_path_etc_issue = '/etc/issue'
    file_path_etc_issue_net = '/etc/issue.net'

    # Check Permissions for the specific files
    print ("\n=============== File Scan for Permissions Starting ===============\n") 

    for file_path in [file_path_etc_motd, file_path_etc_issue, file_path_etc_issue_net]:
        if os.path.exists(file_path):
            file_stat = os.stat(file_path)
            access_mode = stat.filemode(file_stat.st_mode)
            print (f"\nPermissions for {file_path}: {access_mode}")
            report_file.write(f"\n-Permissions for {file_path}: {access_mode}\n")

    print ("\n=============== System Scan Complete ===============\n")
    report_file.write("\n=============== System Scan Completed ===============\n")




def ask_user_scan():

    while True:
        print ("\n=============== Scanning The APT Upgrades and Permissions ===============\n")
        user_choice = input("\nDo you want to perform a scan? (y/n): ").lower()
        if user_choice in ['yes', 'y']:
            return True
        elif user_choice in ['no', 'n']:
            report_file.write("\n=============== Scan Not Initiated ===============\n")
            return False
        else:
            print ("Invalid input. Please enter 'y' or 'n'.")



def perform_apt_upgrade():
    try:

       subprocess.run(['sudo', 'apt', 'update'], check=True)
       subprocess.run(['sudo', 'apt', 'upgrade', '-y'], check=True)
       print ("\nAPT upgrade completed successfully.\n")
       report_file.write("\n-APT upgrade completed successfully.\n")

    except subprocess.CalledProcessError as e:
       print (f"\nError occured during APT upgrade: {e}\n")
       report_file.write("\n-Error has occured during the completion of APT upgrade.\n")



def simulate_apt_upgrade():
    try:

       subprocess.run(['sudo', 'apt', 'update'], check=True)
       result = subprocess.run(['apt', '-s', 'upgrade'], check=True, capture_output=True, text=True)
       print (result.stdout)
       print ("\nAPT simulation upgrade completed.\n")
       report_file.write("\n-APT simulation upgrade completed.\n")

    except subprocess.CalledProcessError as e:
       print (f"\nError occured during the simulation upgrade.\n")
       report_file.write("\n-Error has occured during the completion of simulation APT upgrade.\n")




def run_apt_cache_policy():

    try:
        result = subprocess.run(['apt-cache', 'policy'], check=True, capture_output=True, text=True)
        print (result.stdout)
        print ("\nAPT cache policy view completed\n")
        report_file.write("\n-APT cache policy view completed.\n")
    except subprocess.CalledProcessError as e:
        print (f"\nError has occurred when running 'apt-cache policy': {e}\n")
        report_file.write("\n-Error has occurred when running APT cache policy.\n")


def run_apt_key_list():

    try:
        result = subprocess.run(['apt-key', 'list'], check=True, capture_output=True, text=True)
        print (result.stdout)
        print ("\nGPG keys have been verified.\n")
        report_file.write("\n-APT key list view completed.\n")
    except subprocess.CalledProcessError as e:
        print (f"\nError has occurred when verifying 'apt-key list': {e}\n")
        report_file.write("\n-Error has occurred when verifying APT key list.\n")


def apt_operation_options(simulate=False):

    try:
        print ("\n")
        print ("\n=============== APT Upgrade Configuration ===============\n")
        

       #Prompt the user for choosing between APT upgrade, APT simulation or neither
        print ("Please choose an option:\n")
        print ("1. Perform an APT upgrade\n")
        print ("2. Perform a simulation APT upgrade\n")
        print ("3. Choose neither\n")

        while True:
            choice = input("Enter your choice (1/2/3) : ").strip()
            if choice in ['1', '2', '3']:
                break

            else:
                print ("\nInvalid input. Please choose between 1, 2 or 3.\n")


        if choice == '1':
            perform_apt_upgrade()
        elif choice == '2':
            simulate_apt_upgrade()
        else:
            print ("\nNo APT operation chosen.\n")
            report_file.write("\n-No APT operation chosen from the following.\n")




        while True:
            print ("\n")
            print ("\n=============== Viewing the APT Package Policy ===============\n")
            

            policy_option = input("\nDo you want to view APT package policy? (y/n): ").lower()
            if policy_option in ['y', 'n']:
                break 
            else:
                print ("\nInvalid input. Please enter 'y' or 'n'.\n")

        if policy_option == 'y':
            run_apt_cache_policy()

        elif policy_option == 'n':
              print ("\nAPT package policy not viewed.\n")
              report_file.write("\n-APT package policy not viewed.\n")

        while True:
              print ("\n")
              print ("\n=============== Viewing APT Key List ===============\n")
              

              key_option =  input("\nDo you want to view APT key list? (y/n): ").lower()
              if key_option in ['y', 'n']:
                  break
              else:
                  print ("\nInvalid input. Please enter 'y' or 'n'.\n")

        if key_option == 'y':
            run_apt_key_list()


        elif key_option == 'n':
              print ("\nAPT key lists not viewed.\n")
              report_file.write("\n-APT key lists not viewed.\n")


        
    except subprocess.CalledProcessError as e:
        print (f"\nError occured during APT operation: {e}\n")


def check_etc_motd_for_patterns():

    try:
        with open('/etc/motd', 'r') as motd_file:
            motd_content = motd_file.read()

            #Defining the pattern
            pattern = '==== AUTHORISED USE ONLY. ALL ACTIVITY MAY BE MONITORED AND REPORTED ===='

            #Search for the pattern in the motd content
            match = re.search(pattern, motd_content)

            if match:
                print("\nMOTD Has Been Configured Already. Proceeding .....................!\n")
            else:
                print("\nRecommended MOTD Has Not Been Configured. Proceeding to Configure...\n")
                os.system('echo "==== AUTHORISED USE ONLY. ALL ACTIVITY MAY BE MONITORED AND REPORTED ====" > /etc/motd')
               # print("\nMessage written to /etc/motd file.\n")
                report_file.write("\n-Message has been written to /etc/motd file.\n")
    except FileNotFoundError:
       print ("Error: /etc/motd not found")
    except Exception as e:
       print (f"Error: {e}")
       report_file.write("\n-MOTD Error: {e}")

#Write the message to '/etc/issue.net'
    message = "==== Authorized use only. All activity may be monitored and reported ====\n"

    with open('/etc/issue.net', 'w') as file:
        file.write(message)
        report_file.write("\n-Message written to /etc/issue.net.\n")

#Read the contents of '/etc/issue.net'
    with open('/etc/issue.net', 'r') as file:
        content = file.read()
        print (content)

#Check for patterns in /etc/issue
def check_etc_issue_for_patterns():

    try: 
        #Get the value of the ID field from /etc/os-release
        os_release_id = subprocess.check_output(['grep', '^ID=', '/etc/os-release']).decode('utf-8').split('=')[1].strip().replace('"', '')

        #Construct the pattern 
        pattern = re.compile(f"(\\\v|\\\r|\\\m|\\\s|{os_release_id})", re.IGNORECASE)

        #Search for the pattern in the content of /etc/issue
        with open('/etc/issue', 'r') as issue_file:
            issue_content = issue_file.read()
            match = pattern.search(issue_content)

            if match:
               # print ("\nPattern found in /etc/issue. Proceeding to Modify...\n")
                os.system('echo "Authorized use only. All activity may be monitored and reported." > /etc/issue')
                report_file.write("\n-Issue File has Been Modified. (/etc/issue)")
            else:
                print ("")

    except FileNotFoundError:
        print (f"Error: /etc/issue not found.")
    except subprocess.CalledProcessError as e:
        print (f"Error running 'grep' command: {e}")
    except Exception as e:
        print (f"Error: {e}")


#Check for patterns in /etc/issue.net
#def check_etc_issue_net_for_patterns():
#    try:
        #Get the value of the ID field from /etc/os-release
#        os_release_id = subprocess.check_output(['grep', '^ID=', '/etc/os-release']).decode('utf-8').split('=')[1].strip().replace('"', '')

        #Construct the pattern
#        pattern = re.compile(f"(\\\v|\\\r|\\\m|\\\s|{os_release_id})", re.IGNORECASE)

        #Open and read /etc/issue.net
#        with open('/etc/issue.net', 'r') as issue_net_file:
#            for line in issue_net_file:
#                if re.search(pattern, line, re.IGNORECASE):
#                    print (line.strip()) 


#    except FileNotFoundError:
#        print ("Error: /etc/issue.net not found.")
#    except subprocess.CalledProcessError as e: 
#        print (f"Error running 'grep' command {e}")
#    except Exception as e:
#        print (f"Error: {e}")




def get_file_info_etc_motd(file_path_etc_motd):

    if os.path.exists(file_path_etc_motd):
        file_stat = os.stat(file_path_etc_motd)
        access_mode_octal = oct(file_stat.st_mode & 0o777)  #Extract the permission bits and convert to octal
        access_mode_human = stat.filemode(file_stat.st_mode)
        uid = file_stat.st_uid
        gid = file_stat.st_gid
        username = os.path.basename(os.path.expanduser('~'))
        groupname = os.path.basename(os.path.expanduser('~'))

        report_file.write(f"\nAccess: ({access_mode_octal}/{access_mode_human}) Uid: ({uid}/{username}) Gid: ({gid})/{groupname}) for /etc/motd-\n")
    else:
        report_file.write("\nNothing is returned\n")


file_path_etc_motd = '/etc/motd'
result = get_file_info_etc_motd(file_path_etc_motd)



def display_permission_options_etc_motd():
    print ("\nPermission Options for the etc motd file:\n")
    print ("1. Read (r)\n")
    print ("2. Write (w)\n")
    print ("3. Execute (x)\n")
    print ("4. Read and Write (rw)\n")
    print ("5. Read and Execute (rx)\n")
    print ("6. Write and Execute (wx)\n")
    print ("7. Read, Write and Execute (rwx)\n")



def get_permission_choice_etc_motd():
    while True:
        choice = input("Enter the permission option (1-7): ")
        if choice in ['1', '2', '3', '4', '5', '6', '7']:
            return choice
        else:
            print ("Invalid choice. Please enter a number between 1 and 7.\n")



def get_permissions_from_user_etc_motd():
    display_permission_options_etc_motd()

    owner_permission = get_permission_choice_etc_motd()
    group_permission = get_permission_choice_etc_motd()
    others_permission = get_permission_choice_etc_motd()


    #Convert the choices to corresponding Unix permissions
    permission_mapping = {
        '1': '4', #Read
        '2': '2', #Write
        '3': '1', #Execute
        '4': '6', #Read and Write
        '5': '5', #Read and Execute
        '6': '3', #Write and Execute
        '7': '7', #Read, Write and Execute
    }


    owner_permission_octal = permission_mapping[owner_permission]
    group_permission_octal = permission_mapping[group_permission]
    others_permission_octal = permission_mapping[others_permission]

    # Convert the choices to octal format
    octal_permissions = int(f"{owner_permission_octal}{group_permission_octal}{others_permission_octal}", 8)

    return octal_permissions




def ask_user_to_change_permissions_etc_motd(file_path_etc_motd):
     time.sleep(1)
     #Ask user if they want to change permissions for the etc motd file
     print ("\n")
     print ("\n============== Configuring the etc motd file ===============\n")

     while True:
        change_permissions_input = input("\nDo you want to change permissions for the etc motd file? (y/n): ").lower()
        if change_permissions_input == 'y':
            new_permissions_etc_motd = get_permissions_from_user_etc_motd()
            print (f"\nPermissions for etc motd file changed to {oct(new_permissions_etc_motd)[2:]}\n")
            set_file_permissions_etc_motd(file_path_etc_motd, new_permissions_etc_motd)
            report_file.write("\n-Permissions for etc motd file changed successfully.\n")
            break

        elif change_permissions_input == 'n':
            print ("\nPermissions for etc motd file not changed.\n")
            report_file.write("\n-Permissions for etc motd file not changed.\n")
            break

        else:
            print ("\nInvalid option chosen. Please enter 'y' or 'no'.\n")



def set_file_permissions_etc_motd(file_path_etc_motd, new_permissions_etc_motd):
    try:

        # Set permissions
        os.chmod(file_path_etc_motd, new_permissions_etc_motd)

        print (f"\nPermissions for {file_path_etc_motd} set successfully.\n")

    except OSError as e:
        print (f"\nError occured when setting up permissions for the etc_motd file: {e}\n")




def get_file_info_etc_issue(file_path_etc_issue):

    if os.path.exists(file_path_etc_issue):
        file_stat = os.stat(file_path_etc_issue)
        access_mode_octal = oct(file_stat.st_mode & 0o777)  #Extract the permissi>
        access_mode_human_read = stat.filemode(file_stat.st_mode)
        uid = file_stat.st_uid
        gid = file_stat.st_gid
        username = os.path.basename(os.path.expanduser('~'))
        groupname = os.path.basename(os.path.expanduser('~'))

        report_file.write(f"\nAccess: ({access_mode_octal}/{access_mode_human_read}) Uid: ({uid}/{username}) Gid: ({gid}/{groupname}) for /etc/issue - \n")
    else:
        report_file.write("\nNothing is returned\n")


file_path_etc_issue = '/etc/issue'
result = get_file_info_etc_issue(file_path_etc_issue)



def display_permission_options_etc_issue():
    print ("\nPermission Options for the etc issue file:\n")
    print ("1. Read (r)\n")
    print ("2. Write (w)\n")
    print ("3. Execute (x)\n")
    print ("4. Read and Write (rw)\n")
    print ("5. Read and Execute (rx)\n")
    print ("6. Write and Execute (wx)\n")
    print ("7. Read, Write and Execute (rwx)\n")

def get_permission_choice_etc_issue():
    while True:
        choice = input("\nEnter the permission option (1-7): ")
        if choice in ['1', '2', '3', '4', '5', '6', '7']:
            return choice
        else:
            print ("\nInvalid choice. Please enter a number between 1 and 7.\n")

def get_permissions_from_user_etc_issue():
    display_permission_options_etc_issue()

    owner_permission = get_permission_choice_etc_issue()
    group_permission = get_permission_choice_etc_issue()
    others_permission = get_permission_choice_etc_issue()


    #Convert the choices to corresponding Unix permissions
    permission_mapping = {
        '1': '4', #Read
        '2': '2', #Write
        '3': '1', #Execute
        '4': '6', #Read and Write
        '5': '5', #Read and Execute
        '6': '3', #Write and Execute
        '7': '7', #Read, Write and Execute
    }


    owner_permission_octal = permission_mapping[owner_permission]
    group_permission_octal = permission_mapping[group_permission]
    others_permission_octal = permission_mapping[others_permission]


    # Convert the choices to octal format
    octal_permissions = int(f"{owner_permission_octal}{group_permission_octal}{others_permission_octal}", 8)

    return octal_permissions



def ask_user_to_change_permissions_etc_issue(file_path_etc_issue):
     time.sleep(1)
     #Ask user if they want to change permissions for the etc issue file
     print ("\n")
     print ("\n=============== Configuring the etc issue file ===============\n")



     while True:

        change_permissions_input = input("\nDo you want to change permissions for the etc issue file? (y/n): ").lower()
        if change_permissions_input == 'y':
            new_permissions_etc_issue = get_permissions_from_user_etc_issue()
            print (f"\nPermissions for etc issue file changed to {oct(new_permissions_etc_issue)[2:]}\n")

            set_file_permissions_etc_issue(file_path_etc_issue, new_permissions_etc_issue)
            report_file.write("\n-Permissions for etc issue file changed successfully.\n")
            break

        elif change_permissions_input == 'n':
            print ("\nPermissions for etc issue file not changed.\n")
            report_file.write("\n-Permissions for etc issue file not changed.\n")
            break

        else:
            print ("\nInvalid option chosen. Please enter 'y' or 'n'.\n")






def set_file_permissions_etc_issue(file_path_etc_issue, new_permissions_etc_issue):
    try:

        # Set permissions
        os.chmod(file_path_etc_issue, new_permissions_etc_issue)

        print (f"\nPermissions for {file_path_etc_issue} set successfully.\n")

    except OSError as e:
        print (f"\nError occured when setting up permissions for etc issue file: {e}\n")





def get_file_info_etc_issue_net(file_path_etc_issue_net):

    if os.path.exists(file_path_etc_issue_net):
       file_stat = os.stat(file_path_etc_issue_net)
       access_mode_octal = oct(file_stat.st_mode & 0o777) #Extract the permission bits and convert to octal
       access_mode_human_read = stat.filemode(file_stat.st_mode)
       uid = file_stat.st_uid
       gid = file_stat.st_gid
       username = os.path.basename(os.path.expanduser('~'))
       groupname = os.path.basename(os.path.expanduser('~'))

       report_file.write(f"\nAccess: ({access_mode_octal}/{access_mode_human_read}) Uid: ({uid}/{username}) Gid: ({gid}/{groupname}) for /etc/issue.net -\n")

    else: 
       report_file.write("\nNothing is returned\n") 

file_path_etc_issue_net = '/etc/issue.net'
result = get_file_info_etc_issue_net(file_path_etc_issue_net)




def display_permission_options_etc_issue_net():
    print ("\nPermission Options for the etc issue net file :\n")
    print ("1. Read (r)\n")
    print ("2. Write (w)\n")
    print ("3. Execute (x)\n")
    print ("4. Read and Write (rw)\n")
    print ("5. Read and Execute (rx)\n")
    print ("6. Write and Execute (wx)\n")
    print ("7. Read, Write and Execute (rwx)\n")



def get_permission_choice_etc_issue_net():
    while True:
        choice = input("\nEnter the permission option (1-7): ")
        if choice in ['1', '2', '3', '4', '5', '6', '7']:
            return choice
        else:
            print ("\nInvalid choice. Please enter a number between 1 and 7.\n")




def get_permissions_from_user_etc_issue_net():
    display_permission_options_etc_issue_net()

    owner_permission = get_permission_choice_etc_issue_net()
    group_permission = get_permission_choice_etc_issue_net()
    others_permission = get_permission_choice_etc_issue_net()

    #Convert the choices to corresponding Unix permissions
    permission_mapping = {
        '1': '4', #Read
        '2': '2', #Write
        '3': '1', #Execute
        '4': '6', #Read and Write
        '5': '5', #Read and Execute
        '6': '3', #Write and Execute
        '7': '7', #Read, Write and Execute
    }


    owner_permission_octal = permission_mapping[owner_permission]
    group_permission_octal = permission_mapping[group_permission]
    others_permission_octal = permission_mapping[others_permission]


    # Convert the choices to octal format
    octal_permissions = int(f"{owner_permission_octal}{group_permission_octal}{others_permission_octal}", 8)

    return octal_permissions 




def ask_user_to_change_permissions_etc_issue_net(file_path_etc_issue_net):
     time.sleep(1)
     #Ask user if they want to change permissions for the etc issue net file
     print ("\n")
     print ("\n=============== Configuring the etc issue net file ===============\n")


     while True:

        change_permissions_input = input("\nDo you want to change permissions for the etc issue net file? (y/n): ").lower()
        if change_permissions_input == 'y':
            new_permissions_etc_issue_net = get_permissions_from_user_etc_issue_net()
            print (f"\nPermissions for etc issue net file changed to {oct(new_permissions_etc_issue_net)[2:]}\n")

            set_file_permissions_etc_issue_net(file_path_etc_issue_net, new_permissions_etc_issue_net)
            report_file.write("\n-Permissions for etc issue net file changed successfully.\n")
            break

        elif change_permissions_input == 'n':
            print ("\nPermissions for etc issue net file not changed.\n")
            report_file.write("\n-Permissions for etc issue net file not changed.\n")
            break

        else:
            print ("\nInvalid option chosen. PLease enter 'y' or 'n'.\n")





def set_file_permissions_etc_issue_net(file_path_etc_issue_net, new_permissions_etc_issue_net):
    try:

        # Set permissions
        os.chmod(file_path_etc_issue_net, new_permissions_etc_issue_net)

        print (f"\nPermissions for {file_path_etc_issue_net} set successfully.\n")



    except OSError as e:
        print (f"\nError occured when setting permissions for etc issue net file: {e}\n")

def main():
    initial_head()
    with open(endpath, 'w') as report_file:
         if ask_user_scan():
             scan_system()
         else:
             report_file.write("\n=============== Scan Not Initiated ===============\n")
             print ("\nScan not initiated.\n")
    time.sleep(2)
    check_etc_motd_for_patterns()
    time.sleep(2)
    apt_operation_options(simulate=True)
    time.sleep(2)
    check_etc_issue_for_patterns()
    time.sleep(2)
    #check_etc_issue_net_for_patterns()
    file_path_etc_motd = '/etc/motd' 
    ask_user_to_change_permissions_etc_motd(file_path_etc_motd)
    file_path_etc_issue = '/etc/issue'
    ask_user_to_change_permissions_etc_issue(file_path_etc_issue)
    file_path_etc_issue_net = '/etc/issue.net'
    ask_user_to_change_permissions_etc_issue_net(file_path_etc_issue_net)

main()

report_file.close()


