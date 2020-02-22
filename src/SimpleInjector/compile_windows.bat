rm primitives.py
cp ../misc/primitives.py ./
C:\Python37\python.exe -m PyInstaller simpleInjector.py --onefile -c  --hidden-import primitives
cp dist/* ./
