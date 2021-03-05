# HAFNIUM-IOC
Hafnium-IOC is a simple PowerShell script that runs on Exchange servers to identify indicators of compromises (IOCs) from the Hafnium activity release by Mircosoft on 2021-03-02 (https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/). The script may be updated to include more IOC as more information is made available. 

## License

Hafnium-IOC is under the [MIT license](https://github.com/soteria-security/HAFNIUM-IOC/blob/main/LICENSE) unless explicitly noted otherwise.

## Usage

Due to the nature of Exchange is recommended you run the script on every Exchange server if using a DAG. The script will output findings from both the console and a log file in the current working directory. This setting is also configurable in the variable setting. The script is parameterized to accept the full path of a log file. If no path is provided, a log file will be created in the user's home directory with the name yyyy_MM_dd HH.mm.ss-Hafnium_IOCs.txt.

To execute the script, simply:
```
.\HAFNIUM-Exchange-IOC
```

Or to specify a different log path:
```
.\HAFNIUM-Exchange-IOC -logPath "C:\Temp\Hafnium_Results.log"
```
