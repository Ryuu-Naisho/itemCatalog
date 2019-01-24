# Item Catalog
This is a project that simulates an online catalog, with Oauth2 sign-in. Items and categories can be created, updated, or deleted. To perform CRUD operations on an item, one must be the original creator of the item. There are also api endpoints, more information will be in the usage section. 
    
# Requirements:
- Python 3
- flask*
- sqlalchemy*
- httplib2*
- oauth2client*
- werkzeug*
- Terminal application
If not already installed, you may use ``` sudo pip instal name* ```
# Usage
 - Download or clone the repo
 - With your terminal program (inside the itemCatalog folder) type:
    - First: ```python3 models.py```
    - Then:  ```python3 fillDB.py```
    - Lastly: ```python3 views.py```
 - Once you have typed those lines (excluding the words "first", "then", and "last"). Open your browser and in the address bar type or click: [http://localhost:5000](http://localhost:5000)
 - You will be directed to the home page, on the top left side click the log in button, go ahead and log in with google. Then you'll be redirected to the home page again but with an authenticated user view. From here you may explore, create, or delete items.
 - You may also access these api endpoints:
    - [http://localhost:5000/items/JSON](http://localhost:5000/items/JSON)
        - Retrieves all items.
    - [http://localhost:5000/categories/JSON](http://localhost:5000/categories/JSON)
        - Retrieves all categories.
    - http://localhost:5000/categories/category_name_here/JSON
        - Retreives all items of the given category. 
