A firewall written in C to be run on a linux system.
Uses fwSim to send packets to the firewall which will then process based on rules and user input.

Usage: 
  run the setup_pipes.sh
  interactive usage: ./fwSim -i inputBinary -o outputBinary [-d delay] ./firewall firewallConfig.txt
  scripted usage: ./fwSim -s scriptText -i inputBinary -o outputBinary [-d delay] ./firewall firewallConfig.txt
  
  examples: ./fwSim -i packets.1 -o output.bin ./firewall config1.txt
            ./fwSim -s script1.txt -i packets.1 -o output.bin ./firewall config1.txt
