# Sysmon
Sysmon tool to get all the events we need.
* [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) - Tool used


# Getting Started

First, download and install sysmon,
no dependencies needed
```
Install: Sysmon.exe -i <configfile>
Configure: Sysmon.exe -c <configfile>

sysmon –accepteula –i c:\windows\config.xml

```

# Sysmon Events

List of Sysmon events to monitorize

## Event 1

Identificador de sucesos 1: Creación de proceso

El evento de creación de proceso proporciona información extendida sobre un proceso
recién creado. La línea de comando completa proporciona un contexto en la ejecución
del proceso. El campo ProcessGUID es un valor único para este proceso en un dominio
para facilitar la correlación de eventos. El hash es un hash completo del archivo con los
algoritmos en el campo HashType.

The process creation event provides extended information about a newly created process. 
The full command line provides context on the process execution. 
The ProcessGUID field is a unique value for this process across a domain to make event correlation easier. 
The hash is a full hash of the file with the algorithms in the HashType field.

We exclude the most common dll created in win environments to avoid overflow of logs.
```
		<ProcessCreate onmatch="exclude">
    List of common dlls, can be modified to include whatever we need
```

## Event 2

Identificador de sucesos 2: un proceso cambió un tiempo de creación de archivo
El evento de cambio de tiempo de creación del archivo se registra cuando un proceso
modifica explícitamente la hora de creación del archivo. Este evento ayuda a rastrear el
tiempo real de creación de un archivo. Los atacantes pueden cambiar la hora de creación
del archivo de una puerta trasera para que parezca que se instaló con el sistema
operativo. Tener en cuenta que muchos procesos cambian legítimamente el tiempo de
creación de un archivo; no necesariamente indica actividad maliciosa.

The change file creation time event is registered when a file creation time is explicitly modified by a process.
This event helps tracking the real creation time of a file. Attackers may change the file creation time of a
backdoor to make it look like it was installed with the operating system. Note that many processes legitimately change 
the creation time of a file; it does not necessarily indicate malicious activity.

## Event 3

Identificador de sucesos 3: conexión de red
El evento de conexión de red registra las conexiones TCP / UDP en la máquina. Está
deshabilitado por defecto. Cada conexión está vinculada a un proceso a través de los
campos ProcessId y ProcessGUID. El evento también contiene los nombres de host de
origen y destino, las direcciones IP, los números de puerto y el estado de IPv6.

The network connection event logs TCP/UDP connections on the machine. It is disabled by default. 
Each connection is linked to a process through the ProcessId and ProcessGUID fields. The event
also contains the source and destination host names IP addresses, port numbers and IPv6 status.

## Event 4

Identificador de sucesos 4: estado de servicio Sysmon cambiado
El evento de cambio de estado de servicio informa el estado del servicio Sysmon
(iniciado o detenido).

The service state change event reports the state of the Sysmon service (started or stopped).

## Event 5

El proceso finaliza los informes de eventos cuando finaliza un proceso. Proporciona
UtcTime, ProcessGuid y ProcessId del proceso.

The process terminate event reports when a process terminates. 
It provides the UtcTime, ProcessGuid and ProcessId of the process.

# Event 6

Identificador de sucesos 6: Carga del controlador
Los eventos cargados por el controlador proporcionan información sobre un controlador
que se está cargando en el sistema. Los hashes configurados se proporcionan, así como
la información de la firma. La firma se crea de forma asíncrona por motivos de
rendimiento e indica si el archivo se eliminó después de la carga.

The driver loaded events provides information about a driver being loaded on the system. The configured hashes
are provided as well as signature information. The signature is created asynchronously for performance reasons
and indicates if the file was removed after loading.

# Event 7

Identificador de sucesos 7: Imagen cargada
La imagen cargada registra los eventos cuando un módulo se carga en un proceso
específico. Este evento está deshabilitado de manera predeterminada y debe
configurarse con la opción -l. Indica el proceso en el que se carga el módulo, los hashes
y la información de la firma. La firma se crea de forma asíncrona por motivos de
rendimiento e indica si el archivo se eliminó después de la carga. Este evento debe 
configurarse con cuidado, ya que la supervisión de todos los eventos de carga de
imágenes generará una gran cantidad de eventos.

The image loaded event logs when a module is loaded in a specific process. This event is disabled by 
default and needs to be configured with the –l option. It indicates the process in which the module is 
loaded, hashes and signature information. The signature is created asynchronously for performance reasons 
and indicates if the file was removed after loading. This event should be configured carefully, as monitoring 
all image load events will generate a large number of events.

## Event 8

Identificador de sucesos 8: CreateRemoteThread
El evento CreateRemoteThread detecta cuándo un proceso crea un hilo en otro proceso.
Esta técnica es utilizada por el malware para inyectar código y esconderse en otros
procesos. El evento indica el proceso de origen y destino. Proporciona información
sobre el código que se ejecutará en el nuevo hilo: StartAddress, StartModule y
StartFunction. Tener en cuenta que los campos StartModule y StartFunction se
deducen, pueden estar vacíos si la dirección inicial está fuera de los módulos cargados o
las funciones conocidas exportadas.

The CreateRemoteThread event detects when a process creates a thread in another process. This technique is 
used by malware to inject code and hide in other processes. The event indicates the source and target process. 
It gives information on the code that will be run in the new thread: StartAddress, StartModule and StartFunction.
Note that StartModule and StartFunction fields are inferred, they might be empty if the starting address is outside 
loaded modules or known exported functions.

## Event 9

Identificador de sucesos 9: RawAccessRead
El evento RawAccessRead detecta cuándo un proceso realiza operaciones de lectura
desde el disco utilizando la denotación \\. \. Esta técnica a menudo es utilizada por
malware para la extracción de datos de archivos que están bloqueados para su lectura,
así como para evitar herramientas de auditoría de acceso a archivos. El evento indica el
proceso de origen y el dispositivo de destino.

The RawAccessRead event detects when a process conducts reading operations from the drive using the \\.\ denotation. 
This technique is often used by malware for data exfiltration of files that are locked for reading, as 
well as to avoid file access auditing tools. The event indicates the source process and target device.

## Event 10

Identificador de sucesos 10: ProcessAccess
El proceso accedió a informes de eventos cuando un proceso abre otro proceso, una
operación que a menudo es seguida por consultas de información o lectura y escritura
del espacio de direcciones del proceso objetivo. Esto permite la detección de
herramientas de pirateo que leen el contenido de la memoria de procesos como Local
Security Authority (Lsass.exe) para robar credenciales para usar en ataques Pass-the-
Hash. Habilitarlo puede generar cantidades significativas de registro si hay utilidades de
diagnóstico activas que abren repetidamente procesos para consultar su estado, por lo
que generalmente solo se debe hacer con filtros que eliminen los accesos esperados.

The process accessed event reports when a process opens another process, an operation that’s often 
followed by information queries or reading and writing the address space of the target process. 
This enables detection of hacking tools that read the memory contents of processes like Local Security 
Authority (Lsass.exe) in order to steal credentials for use in Pass-the-Hash attacks. Enabling it can generate 
significant amounts of logging if there are diagnostic utilities active that repeatedly open processes to query 
their state, so it generally should only be done so with filters that remove expected accesses.

## Event 11

Identificador de sucesos 11: FileCreate
Las operaciones de creación de archivos se registran cuando se crea o sobrescribe un
archivo. Este evento es útil para monitorear ubicaciones de inicio automático, como la
carpeta de inicio, así como directorios temporales y de descarga, que son lugares
comunes donde el malware se cae durante la infección inicial.

File create operations are logged when a file is created or overwritten. This event is useful for
monitoring autostart locations, like the Startup folder, as well as temporary and download directories, 
which are common places malware drops during initial infection.

## Event 12

Identificador de sucesos 12: RegistryEvent (crear y eliminar objetos)
La clave del registro y el valor crean y eliminan el mapa de operaciones para este tipo
de evento, que puede ser útil para monitorear los cambios en las ubicaciones de inicio
automático del Registro o las modificaciones específicas del registro de malware

Registry key and value create and delete operations map to this event type, which can be useful for 
monitoring for changes to Registry autostart locations, or specific malware registry modifications.

## Event 13

Identificador de sucesos 13: RegistryEvent (conjunto de valores)
Este tipo de evento de registro identifica modificaciones de valores de registro. El
evento registra el valor escrito para los valores de Registro de tipo DWORD y QWORD.

This Registry event type identifies Registry value modifications. The event records the value
written for Registry values of type DWORD and QWORD.

## Event 14

Identificador de sucesos 14: RegistryEvent (Key and Value Rename)
Las operaciones de cambio de nombre y clave de registro se asignan a este tipo de
evento, registrando el nuevo nombre de la clave o valor que fue renombrado.

Registry key and value rename operations map to this event type, recording the new name of the key or value that was renamed.

## Event 15

Identificador de sucesos 15: FileCreateStreamHash
Este evento se registra cuando se crea una secuencia de archivos con nombre y genera
eventos que registran el hash de los contenidos del archivo al que se asigna la secuencia
(la secuencia sin nombre), así como los contenidos de la secuencia con nombre. Existen
variantes de malware que eliminan sus ejecutables o configuraciones mediante las
descargas del navegador, y este evento está dirigido a capturar eso basado en el
navegador adjuntando una secuencia de "marca de la web"

This event logs when a named file stream is created, and it generates events that log the hash of the 
contents of the file to which the stream is assigned (the unnamed stream), as well as the contents of
the named stream. There are malware variants that drop their executables or configuration settings via 
browser downloads, and this event is aimed at capturing that based on the browser attaching a Zone.Identifier
“mark of the web” stream.

## Event 17

Identificador de sucesos 17: PipeEvent
Este evento se genera cuando se crea una pipe con nombre. El malware a menudo usa
canalizaciones con nombre para la comunicación entre procesos.

This event generates when a named pipe is created. Malware often uses named pipes for interprocess communication.

## Event 18

Identificador de sucesos 18: PipeEvent (Pipe Connected)
Este evento se registra cuando se establece una conexión de canalización con nombre
entre un cliente y un servidor.

This event logs when a named pipe connection is made between a client and a server.

## Event 19

Identificador de sucesos 19: WmiEvent (actividad de WmiEventFilter detectada)
Cuando se registra un filtro de eventos de WMI, que es un método que utiliza el
malware para ejecutar, este evento registra el espacio de nombres de WMI, el nombre de
filtro y la expresión de filtro.

When a WMI event filter is registered, which is a method used by malware to execute, 
this event logs the WMI namespace, filter name and filter expression.

## Event 20

Identificador de sucesos 20: WmiEvent (actividad de WmiEventConsumer
detectada)Este evento registra el registro de los consumidores de WMI, registrando el nombre del
consumidor, el registro y el destino.

This event logs the registration of WMI consumers, recording the consumer name, log, and destination.

## Event 21

Identificador de sucesos 21: WmiEvent (actividad WmiEventConsumerToFilter
detectada)Cuando un consumidor se une a un filtro, este evento registra el nombre del consumidor y la ruta del filtro.

When a consumer binds to a filter, this event logs the consumer name and filter path.



## Event 255

Identificador de sucesos 255: error
Este evento se genera cuando ocurre un error dentro de Sysmon. Pueden suceder si el
sistema está bajo mucha carga y no se pudo realizar determinada tarea o existe una falla
en el servicio Sysmon.

This event is generated when an error occurred within Sysmon. They can happen if the system is under heavy load and 
certain tasked could not be performed or a bug exists in the Sysmon service. 

## Credits
All credits to Mark Russinovich. You can report any bugs on the Sysinternals forum or over Twitter (@markrussinovich).
