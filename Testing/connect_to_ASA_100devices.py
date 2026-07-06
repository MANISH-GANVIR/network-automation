from netmiko import ConnectHandler
def main():
    try:
        devices=["1.1.1.1","2.2.2.2","3.3.3.3"]
        for ip in devices:
            try:
                device={
                    "device_type": "cisco_ios",
                    "username": "admin",
                    "password": "admin",
                    "host": ip,
                    "secret": "cisco"
                }

                conn=ConnectHandler(**device)
                conn.enable()
                show_run=conn.send_command("show run")
                print(show_run)
                output_file_path=rf"D:\{device['host']} "
                open_output_file_path =open(output_file_path,"w")
                open_output_file_path.write(show_run)
                open_output_file_path.close()
                conn.disconnect()

            except Exception as e:
                print("Device Error:",e)

    except Exception as e:
        print("Error:/t",e)
if __name__=="__main__":
    main()