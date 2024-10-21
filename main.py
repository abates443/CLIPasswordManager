from database import *
from encryption import *
from getpass import getpass
import clipboard
import os


def main():
    # Setup database
    global user_id, key, master_user
    setup_database()
    login_options = ""
    menu_options = ""
    print("       .--------.\n"
          "      / .------. \ \n"
          "     / /        \ \ \n"
          "     | |        | | \n"
          "    _| |________| |_ \n"
          "  .' |_|        |_| '.\n"
          "  '._____ ____ _____.'\n"
          "  |     .'____'.     |\n"
          "  '.__.'.'    '.'.__.'\n"
          "  |.__  |      |  __.|\n"
          "  |   '.'.____.'.'   |\n"
          "  '.____'.____.'____.'\n"
          "  '.________________.'\n"
          "bootCon Password Manager")
    input("")
    while login_options != "3":
        print("Login:\n"
              "1. New user\n"
              "2. Existing user\n"
              "3. Exit\n")
        login_choice = input("Select option number: ")
        if login_choice == "1":
            '''
            New User
            '''
            master_user = input("Enter your username: ")
            master_password = getpass("Enter your master password: ")
            # os.system('cls')

            # Create a key and store auth for the new user, then retrieve the user id for application to use later
            master_hash = gen_hash(master_password)
            key = derive_key(master_password)
            if new_user(master_user, master_hash) == -1:
                os.system('cls')
                print("Username taken. Try logging in as an existing user, or select a different username.\n")
                menu_options = "5"
            else:
                user_id = login(master_user, master_hash)

                os.system('cls')
                print("Welcome, " + master_user + "!")
                menu_options = ""
            # Clear stored master password
            del master_password

        elif login_choice == "2":
            master_user = input("Enter your username: ")
            master_password = getpass("Enter your master password: ")
            # os.system('cls')

            # Create a key and store auth for the new user, then retrieve the user id for application to use later
            master_hash = gen_hash(master_password)
            key = derive_key(master_password)

            if check_exist(master_user) == -1:
                os.system('cls')
                print("User not found. Try logging in as a new user.\n")
                menu_options = "5"
            elif login(master_user, master_hash) == -1:
                os.system('cls')
                print("Password incorrect, please try logging in again.\n")
                menu_options = "5"
            else:
                user_id = login(master_user, master_hash)
                os.system('cls')
                print("Welcome back, " + master_user + "!")
                menu_options = ""
            # Clear stored master password
            del master_password
        elif login_choice == "3":
            break
        else:
            os.system('cls')
            print("Invalid input, please enter a number between 1-3\n")
            menu_options = "5"
        """
        ADD MENU OPTIONS
        """
        while menu_options != "5":
            print("1. Store/Update credentials\n"
                  "2. Retrieve password\n"
                  "3. Delete credentials\n"
                  "4. Display all credentials\n"
                  "5. Logout\n")

            menu_options = input("Select option number: ")

            if menu_options == "1":

                '''
                Store/Update credentials
                '''
                print("Enter the service and username:\n"
                      "eg. Service name: Gmail\n"
                      "    Username: ExampleUser\n")
                service_name = input("Service name: ")
                username = input("Username: ")
                # Present option to enter existing password or generate new password
                store_options = ""
                print("1. Generate random password?\n"
                      "2. Enter existing password\n"
                      "3. Return to menu\n")
                while store_options != "3":
                    store_options = input("Select option number: ")
                    # Generate random password
                    if store_options == "1":
                        password = generate_secure_password()
                        enc_password = encrypt_password(password, key)
                        status = add_credentials(user_id, service_name, username, enc_password)
                        if status == 1:
                            print(service_name + " password for " + username + " stored!")
                            cpy_check = 0
                            while cpy_check != 1:
                                user_input = input(
                                    "Would you like to copy the password to your clipboard? (Y/N): ").upper()
                                if user_input == "Y":
                                    clipboard.copy(password)
                                    print("Password copied to clipboard!\n")
                                    cpy_check = 1
                                    input("Press Enter to return to menu...")
                                    os.system('cls')
                                elif user_input == "N":
                                    print("Password was not copied to clipboard.\n")
                                    cpy_check = 1
                                    input("Press Enter to return to menu...")
                                    os.system('cls')
                                else:
                                    print("Invalid input, please enter 'Y' or 'N'.")
                        else:
                            print(service_name + " password for " + username + " already exists!")
                            overwrite_check = 0
                            while overwrite_check != 1:
                                user_input = input("Update existing password? (Y/N): ").upper()
                                if user_input == "Y":
                                    failures = 0
                                    while failures < 3:
                                        print("You are about to update this password!")
                                        conf = getpass("For confirmation, please enter your master password: ")
                                        verify = check_auth(user_id, gen_hash(conf))
                                        if verify == 1:
                                            delete_credentials(user_id, service_name, username)
                                            add_credentials(user_id, service_name, username, enc_password)
                                            print("Password updated!")
                                            overwrite_check = 1
                                            cpy_check = 0
                                            while cpy_check != 1:
                                                user_input = input(
                                                    "Would you like to copy the password to your clipboard?"
                                                    " (Y/N): ").upper()
                                                if user_input == "Y":
                                                    clipboard.copy(password)
                                                    print("Password copied to clipboard!\n")
                                                    cpy_check = 1
                                                    input("Press Enter to return to menu...")
                                                    os.system('cls')
                                                elif user_input == "N":
                                                    print("Password was not copied to clipboard.\n")
                                                    cpy_check = 1
                                                    input("Press Enter to return to menu...")
                                                    os.system('cls')
                                                else:
                                                    print("Invalid input, please enter 'Y' or 'N'.")
                                            break
                                        else:
                                            failures += 1
                                            remaining = (3 - failures)
                                            if remaining > 0:
                                                print(
                                                    "Master password incorrect. " + str(remaining) +
                                                    " attempts remaining.")
                                            else:
                                                os.system('cls')
                                                print("Unauthorized activity suspected, please log back in.\n")
                                                menu_options = "5"
                                                overwrite_check = 1
                                elif user_input == "N":
                                    overwrite_check = 1
                                    print("Password will not be updated.\n")
                                    input("Press Enter to return to menu...")
                                    os.system('cls')
                                else:
                                    print("Invalid input, please enter 'Y' or 'N'.")
                        del password
                        break
                    # Enter own password
                    elif store_options == "2":
                        password = getpass("Enter password: ")
                        enc_password = encrypt_password(password, key)
                        status = add_credentials(user_id, service_name, username, enc_password)
                        if status == 1:
                            print(service_name + " credentials for " + username + " stored!")
                            cpy_check = 0
                            while cpy_check != 1:
                                user_input = input(
                                    "Would you like to copy the password to your clipboard? (Y/N): ").upper()
                                if user_input == "Y":
                                    clipboard.copy(password)
                                    print("Password copied to clipboard!\n")
                                    cpy_check = 1
                                    input("Press Enter to return to menu...")
                                    os.system('cls')
                                elif user_input == "N":
                                    print("Password was not copied to clipboard.\n")
                                    cpy_check = 1
                                    input("Press Enter to return to menu...")
                                    os.system('cls')
                                else:
                                    print("Invalid input, please enter 'Y' or 'N'.")
                        else:
                            print(service_name + " credentials for " + username + " already exist!\n")
                            overwrite_check = 0
                            while overwrite_check != 1:
                                user_input = input("Update existing password? (Y/N): ").upper()
                                if user_input == "Y":
                                    failures = 0
                                    while failures < 3:
                                        print("You are about to update this password!")
                                        conf = getpass("For confirmation, please enter your master password: ")
                                        verify = check_auth(user_id, gen_hash(conf))
                                        if verify == 1:
                                            delete_credentials(user_id, service_name, username)
                                            add_credentials(user_id, service_name, username, enc_password)
                                            print("Password updated!")
                                            overwrite_check = 1
                                            cpy_check = 0
                                            while cpy_check != 1:
                                                user_input = input(
                                                    "Would you like to copy the password to your "
                                                    "clipboard? (Y/N): ").upper()
                                                if user_input == "Y":
                                                    clipboard.copy(password)
                                                    print("Password copied to clipboard!\n")
                                                    cpy_check = 1
                                                    input("Press Enter to return to menu...")
                                                    os.system('cls')
                                                elif user_input == "N":
                                                    print("Password was not copied to clipboard.\n")
                                                    cpy_check = 1
                                                    input("Press Enter to return to menu...")
                                                    os.system('cls')
                                                else:
                                                    print("Invalid input, please enter 'Y' or 'N'.")
                                            break
                                        else:
                                            failures += 1
                                            remaining = (3 - failures)
                                            if remaining > 0:
                                                print(
                                                    "Master password incorrect. " + str(remaining) +
                                                    " attempts remaining.")
                                            else:
                                                os.system('cls')
                                                print("Unauthorized activity suspected, please log back in.")
                                                menu_options = "5"
                                                overwrite_check = 1
                                elif user_input == "N":
                                    overwrite_check = 1
                                    print("Password will not be updated.\n")
                                    input("Press Enter to return to menu...")
                                    os.system('cls')
                                else:
                                    print("Invalid input, please enter 'Y' or 'N'.")
                        del password
                        break
                    # Exit
                    elif store_options == "3":
                        break
                    else:
                        print("Invalid input, please enter a number between 1-3")

            elif menu_options == "2":
                '''
                Retrieve password
                '''
                print("Enter the service and username of the password you want to retrieve:\n"
                      "eg. Service name: Gmail\n"
                      "    Username: ExampleUser\n")
                service_name = input("Service name: ")
                username = input("Username: ")
                enc_password = retrieve_password(user_id, service_name, username)
                # If check returns 0, no entry matching the provided service/username combo exists.
                if enc_password == 0:
                    print("No password found matching " + service_name + " and " + username + ".\n")
                    input("Press Enter to return to menu...")
                    os.system('cls')
                # Otherwise, copy decrypted password to clipboard
                else:
                    dec_password = decrypt_password(enc_password, key)
                    clipboard.copy(dec_password)
                    print("Password copied to clipboard!\n")
                    input("Press Enter to return to menu...")
                    os.system('cls')

            elif menu_options == "3":
                '''
                Delete credentials
                '''
                print("Enter the service and username of the password you want to delete:\n"
                      "eg. Service name: Gmail\n"
                      "    Username: ExampleUser\n")
                service_name = input("Service name: ")
                username = input("Username: ")
                check = retrieve_password(user_id, service_name, username)
                # If check returns 0, no entry matching the provided service/username combo exists.
                if check == 0:
                    print("No entry found matching " + service_name + " and " + username + ".")
                # Otherwise, use master password as confirmation to delete the selected entry.
                # If master password is entered wrong three times, user will be logged out completely.
                else:
                    failures = 0
                    while failures < 3:
                        print("You are about to delete these credentials!")
                        conf = getpass("For confirmation, please enter your master password: ")
                        verify = check_auth(user_id, gen_hash(conf))
                        if verify == 1:
                            delete_credentials(user_id, service_name, username)
                            print("Credentials deleted!\n")
                            input("Press Enter to return to menu...")
                            os.system('cls')
                            break
                        else:
                            failures += 1
                            remaining = (3 - failures)
                            if remaining > 0:
                                print("Master password incorrect. " + str(remaining) + " attempts remaining.")
                            else:
                                os.system('cls')
                                print("Unauthorized activity suspected, please log back in.\n")
                                menu_options = "5"
            elif menu_options == "4":
                '''
                Show all credentials
                '''
                print("You are about to display all stored credential pairs for " + master_user)
                failures = 0
                while failures < 3:
                    conf = getpass("For confirmation, please enter your master password: ")
                    verify = check_auth(user_id, gen_hash(conf))
                    if verify == 1:
                        show_all(user_id)
                        input("\nPress Enter to return to menu...")
                        os.system('cls')
                        break
                    else:
                        failures += 1
                        remaining = (3 - failures)
                        if remaining > 0:
                            print("Master password incorrect. " + str(remaining) + " attempts remaining.")
                        else:
                            os.system('cls')
                            print("Unauthorized activity suspected, please log back in.\n")
                            menu_options = "5"
            elif menu_options == "5":
                os.system('cls')
                break
            else:
                os.system('cls')
                print("Invalid input, please enter a number between 1-5\n")


os.system('cls')
main()
