# SysInfo (C)

Ferramenta simples em C para Windows que coleta informações do sistema e escreve um relatório em um arquivo `sysinfo_YYYYMMDD_hhmmss.txt`.

**Funcionalidades**
- Informações básicas do sistema (nome do computador, usuário, OS)
- Informações de CPU (vendor, brand via CPUID)
- Memória RAM (GlobalMemoryStatusEx)
- Informações de disco / volumes
- Adaptadores de rede e IPs (GetAdaptersAddresses)
- Drivers carregados (EnumDeviceDrivers)
- Dispositivos presentes (SetupAPI)
- Serviços Windows (EnumServicesStatusEx)
- Algumas chaves do Registro (ProductName)

**Compilar**
- MinGW:
  `gcc sysinfo.c -o sysinfo.exe -lsetupapi -liphlpapi -lpsapi -lws2_32 -ladvapi32`

- Visual Studio (Developer Command Prompt):
  `cl /EHsc sysinfo.c /link setupapi.lib iphlpapi.lib psapi.lib ws2_32.lib advapi32.lib`

**Uso**
- Execute `sysinfo.exe`. Ele gerará um arquivo `sysinfo_*.txt` no diretório atual.
- Para informações completas, execute como Administrador.

**Observações**
- Algumas informações podem não ser retornadas se o usuário não tiver permissões suficientes.
- Testado em Windows 10/11 (x64). Ajustes podem ser necessários para builds 32-bit ou versões antigas.

**Licença**
GPL3

