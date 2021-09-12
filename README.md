# formcreationapp
formcreationapp
# CAPSTONE PROJECT: Make a TypeForm Clone using Flask
```
$ flask routes
Endpoint       Methods    Rule
-------------  ---------  -----------------------
add_user       GET, POST  /user/add
create_FIOB    GET, POST  /forms/fiob
create_FITB    GET, POST  /forms/fitb
create_dd      GET, POST  /forms/dd
create_form    GET, POST  /forms/create
create_likert  GET, POST  /forms/likert
create_ma      GET, POST  /forms/ma
create_mcq     GET, POST  /forms/create-mcq
create_pma     GET, POST  /forms/pma
create_pmcq    GET, POST  /forms/pmcq
create_upload  GET, POST  /forms/upload
dashboard      GET, POST  /dashboard
delete         GET        /delete/<int:id>
edit_form      GET        /forms/edit/<hash>
form           GET        /forms/<hash>
index          GET        /
login          GET, POST  /login
logout         GET, POST  /logout
name           GET, POST  /name
nameform       GET, POST  /forms/name-setter
next_question  GET, POST  /forms/create-new
static         GET        /static/<path:filename>
update         GET, POST  /update/<int:id>
user           GET        /user/<name>
```

### TypeForm
* An engaging web form that aimed at increased completion rates<br/>
* Supports custom layouts, themes and can add photos, videos along side the questions <br/>
* Demo can be seen [here](https://www.youtube.com/watch?v=OcWbNM4hDsc) <br/>

### Flask-WTF
* WTF forms Provides interactive interface for the user <br/>
* Offers global protection with CSRF tokens <br/>
* Can be used for Python Web Development <br/>
* Documentation can be accessed [here](https://wtforms.readthedocs.io/en/2.3.x/)

### Objective
Develop a Typeform Clone with the following features <br/>
1. Simple login (username: tsai, password: tsai99!) and logout. <br/>
2. Workspace to see forms already created, and a button to create a new form.<br/>
3. Need to have Editor and Logic (Design is optional)<br/>
4. Must implement 2 options is the layout (question on top of image, or image is on side of the question)<br/>
5. Share is required (gives a public url that can be used to fill in the form)<br/>
6. Must write rigorous testing logic to check for cyclic or impossible to implement logic flows<br/>
7. Must implement Results, and each form/test result (final) must be available as future logs to be seen.<br/>
8. Must implement the "timed" feature (quiz to be closed after 10 minutes, etc)<br/>
9. Allow a user to download the made quiz (as txt/json/etc), and change something inside, and upload it back to make a new quiz automatically! <br/>
10. Must be hosted on HEROKU (at least) or AWS (if you are comfortable or have time). <br/>
11. Templates are not required. Focus is not on UI/Tabs, etc, but features. So it is OK to have buttons and NOT TABS. <br/>
<br/>

**MileStones**: The Capstone project development is divided into 3 phases.<br/>
```bash
# Phase-1
Submit a simple flask app hosted on Heroku showing your name as the title of the page.
And the app that was developed in the video
# Phase-2
Complete the app (including the test cases) minus the upload/download feature
# Phase-3
Complete the app (including all possible test cases) including the upload/download feature
```

I am currently working on Phase-1 development. The repo contains code to develop a simple flask app hosted on heroku.
The repository will be regularly updated to include changes. <br/>

### Deployment
* Heroku deployment can be found [here](https://epai3-capstone-kranti.herokuapp.com/) <br/>
* Alternately the code can be downloaded and can see the output at local server: http://127.0.0.1:5000/ <br/>

### Phase-1
1. A simple user form which takes 'name' input from user is developed using Flask-WTF.<br/>
2. The web page title is changed to my name rather than the default name. <br/>
2. The app is deployed onto web using Heroku Platform.<br/>
3. The user form contains a name field that seeks input from user. The following rules are applied for the name field.<br/>
	(i) Name field supports all alphabets, alphabets coupled with numerals, period, underscore are allowed.<br/>
	(ii) All empty spaces, All numerals, Special Characters are not allowed.<br/>
	(iii) Input text length should not exceed 50 characters.<br/>
4. If the input text is all CAPS, it is rendered as is else the first letter is capitalized and rendered. <br/>
5. The errors generated in the input text are catched inside flask template and shown to user for quick correction.<br/>

### Task achieved
Able to dump the  diferent type of form and questions to json data. Json dump of the form can be share with the link.
