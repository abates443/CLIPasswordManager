A simple Windows CLI-based password manager I wrote for my final project during a cybersecurity course.

I utitlized the SQLITE3 and Fernet modules for Python to create a simple database that stores login information using symmetric encryption.

The PM uses simple prompts to guide the user in it's usage, it supports multiple users without sharing the individual users details with each other.

![image](https://github.com/user-attachments/assets/6d6719bf-616a-4e96-85c5-a8c6faef0200)

Account creation involves setting a username and a master password, the hash of which is involved in creating the symmetric encryption key for the stored passwords. The master password itself is not stored in plaintext anywhere in the database.

![image](https://github.com/user-attachments/assets/38dda092-7a02-4eeb-ad77-b184d2db2de4)

Upon logging in, the user is presented with the options to store/update existing, retrieve, delete, and view all stored credentials, as well as the option to log out of their account.

![image](https://github.com/user-attachments/assets/29eaf68c-a224-4865-8db5-ce18dc6df974)

While logged in, you can freely store new credential pairs, with the option to manually enter your own password, or have the PM generate a random 12 character password for you.
In the event that the user enters a service/username pair that already exists on their account, the PM will check whether they want to update the currently stored password for that pairing.

![image](https://github.com/user-attachments/assets/b117f6cf-4c4c-4530-b8a0-001cb26129be)

For an extra layer of authentication (for example: in the event that the user would leave their account logged in, and someone else accessed the computer), updating, viewing, or deleting stored credentials requires reinput of the users master password.

![image](https://github.com/user-attachments/assets/3dc24e33-0241-4855-bfc2-acb5e22d5cd5)

After 3 failed attempts, it will log the user out.

![image](https://github.com/user-attachments/assets/0f9adc0c-a11e-475c-bf53-cebe2d850b69)

