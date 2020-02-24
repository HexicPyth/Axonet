rm primitives.py
cp ../misc/primitives.py ./
python3 -m PyInstaller simpleInjector.py --onefile -c  --hidden-import primitives
cp dist/* ./
