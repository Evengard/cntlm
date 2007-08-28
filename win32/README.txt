Cntlm Installation Manual for Windows
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Extract the contents of the distribution ZIP archive into a temporary location.
Then enter the extracted "cntlm-install" folder and run "setup.bat". This will
install Cntlm into the Program Files folder and register a new windows service
"cntlm", which can be managed by standard windows tools. If you are updating
an older version, setup will not overwrite your configuration file, but some
relases may have new options or important comments in the distributed cntlm.ini
template; it might be worth the while to look at it.

To configure Cntlm, go
to %PROGRAMFILES%\Cntlm (usually C:\Program Files\Cntlm) and edit the file
"cntlm.ini".

You may want to check configuration tips online at http://cntlm.sourceforge.net/


Starting and stopping
~~~~~~~~~~~~~~~~~~~~~
Go to the Service management applet:
Start -> Settings -> Control Panel -> Administrative Tools -> Services
or
Start -> Run, write "services.msc" and press enter.

When you have the Services window in front of you, right-click the line named
"Cntlm Authentication Proxy" and select "Start" or "Stop" respectively. Other
options like automatic/manual startup can be configured via the "Properties"
menu. The same can be accomplished using the command line:

net start cntlm
or
net stop cntlm


Uninstalling
~~~~~~~~~~~~
First stop the service and then go to the folder, where Cntlm was installed.
Run the batch "uninstall.bat", which will unregister the windows service and
then you can safely delete the whole directory.
