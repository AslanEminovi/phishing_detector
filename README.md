phishing_detector

simple python tool that detects phishing links.
to run the program

python train_model.py python app.py
in case you get dependecy error

pip install -r requirements.txt
in case you get virtual environment problem

cd /path/"to_the_folder_path"/ source venv/bin/activate python app.py
to check if the link plans to phish you

open new terminal and type: curl -X POST -H "Content-Type: application/json" -d '{"url":"http://example.com/login"}' http://127.0.0.1:5000/predict
