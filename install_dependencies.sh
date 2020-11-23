sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install tshark -y
sudo apt install python3-pip -y
pip3 install --upgrade pip
pip3 install -r requirements.txt 
sudo apt-get install libxcb-xinerama0
echo "Enabling packets forwarding.."
sudo ./enable_packets_forwarding.sh
echo "Enabling done"
echo "Please reboot system now!"

