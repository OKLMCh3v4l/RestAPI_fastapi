import fastapi
import pydantic
from jose import jwt
import fastapi.security
import fastapi.exceptions

app = fastapi.FastAPI()

all_users = {
    "admin": {"id": 1, "username": "admin", "password": "password"},
    "user1": {"id": 2, "username": "user1", "password": "password1"},
    "user2": {"id": 3, "username": "user2", "password": "password2"}
}

all_products = [
    {"id": 1, "name": "Banane", "price": 1},
    {"id": 2, "name": "Pomme", "price": 2}
]

all_carts = []

class User(pydantic.BaseModel):
    id: int
    username: str

class Product(pydantic.BaseModel):
    id: int
    name: str
    price: int

class CartItem(pydantic.BaseModel):
    product_id: int
    quantity: int

class Cart(pydantic.BaseModel):
    id: int
    items: list[CartItem] = []

def create_access_token(data):
    return jwt.encode(data.copy(), "SECRET_KEY", algorithm="HS256")

def get_user(username):
    return all_users.get(username)

oauth2_scheme = fastapi.security.OAuth2PasswordBearer(tokenUrl="token")

def verify_token(token):
    try:
        payload = jwt.decode(token, "SECRET_KEY", algorithms=["HS256"])
        username = payload.get("sub")
        if username is None:
            raise fastapi.exceptions.HTTPException(status_code=401, detail="Invalid token")
        return get_user(username)
    except jwt.JWTError:
        raise fastapi.exceptions.HTTPException(status_code=401, detail="Invalid token")

# login endpoint
@app.post("/login")
async def login(form_data: fastapi.security.OAuth2PasswordRequestForm = fastapi.Depends()):
    user = get_user(form_data.username)
    if not user or form_data.password != all_users[form_data.username]["password"]:
        raise fastapi.exceptions.HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# user endpoints
@app.get("/users")
async def read_users(token: str = fastapi.Depends(oauth2_scheme)):
    verify_token(token)
    return [{"id": user["id"], "username": user["username"]} for user in all_users.values()]

@app.post("/users")
async def create_user(user: User, token: str = fastapi.Depends(oauth2_scheme)):
    verify_token(token)
    if user.username in all_users:
        raise fastapi.exceptions.HTTPException(status_code=400, detail="Username already exists")
    if any(existing_user["id"] == user.id for existing_user in all_users.values()):
        raise fastapi.exceptions.HTTPException(status_code=400, detail="User ID already exists")
    
    all_users[user.username] = {"id": user.id, "username": user.username, "password": "password"}
    return user

@app.get("/users/{user_id}")
async def read_user(user_id: int, token: str = fastapi.Depends(oauth2_scheme)):
    verify_token(token)
    for user in all_users.values():
        if user["id"] == user_id:
            return user
    raise fastapi.exceptions.HTTPException(status_code=404, detail="User not found")

@app.put("/users/{user_id}")
async def update_user(user_id: int, updated_user: User, token: str = fastapi.Depends(oauth2_scheme)):
    verify_token(token)
    for username, user in all_users.items():
        if user["id"] == user_id:
            user["username"] = updated_user.username
            return user
    raise fastapi.exceptions.HTTPException(status_code=404, detail="User not found")

@app.delete("/users/{user_id}")
async def delete_user(user_id: int, token: str = fastapi.Depends(oauth2_scheme)):
    verify_token(token)
    for username, user in list(all_users.items()):
        if user["id"] == user_id:
            del all_users[username]
            return {"detail": "User deleted"}
    raise fastapi.exceptions.HTTPException(status_code=404, detail="User not found")

# products endpoint
@app.get("/products")
async def read_products(token: str = fastapi.Depends(oauth2_scheme)):
    verify_token(token)
    return all_products

@app.post("/products")
async def create_product(product: Product, token: str = fastapi.Depends(oauth2_scheme)):
    verify_token(token)
    if any(existing_product["id"] == product.id for existing_product in all_products):
        raise fastapi.exceptions.HTTPException(status_code=400, detail="Product ID already exists")
    
    all_products.append(product.dict())
    return product

@app.get("/products/{product_id}")
async def read_product(product_id: int, token: str = fastapi.Depends(oauth2_scheme)):
    verify_token(token)
    for product in all_products:
        if product["id"] == product_id:
            return product
    raise fastapi.exceptions.HTTPException(status_code=404, detail="Product not found")

@app.put("/products/{product_id}")
async def update_product(product_id: int, updated_product: Product, token: str = fastapi.Depends(oauth2_scheme)):
    verify_token(token)
    for index, product in enumerate(all_products):
        if product["id"] == product_id:
            all_products[index] = updated_product.dict()
            all_products[index]["id"] = product_id
            return all_products[index]
    raise fastapi.exceptions.HTTPException(status_code=404, detail="Product not found")

@app.delete("/products/{product_id}")
async def delete_product(product_id: int, token: str = fastapi.Depends(oauth2_scheme)):
    verify_token(token)
    for index, product in enumerate(all_products):
        if product["id"] == product_id:
            del all_products[index]
            return {"detail": "Product deleted"}
    raise fastapi.exceptions.HTTPException(status_code=404, detail="Product not found")

# carts endpoints
@app.get("/carts")
async def read_carts(token: str = fastapi.Depends(oauth2_scheme)):
    verify_token(token)
    return all_carts

@app.post("/carts")
async def create_cart(cart: Cart, token: str = fastapi.Depends(oauth2_scheme)):
    verify_token(token)
    if any(existing_cart["id"] == cart.id for existing_cart in all_carts):
        raise fastapi.exceptions.HTTPException(status_code=400, detail="Cart ID already exists")
    
    all_carts.append(cart.dict())
    return cart

@app.get("/carts/{cart_id}")
async def read_cart(cart_id: int, token: str = fastapi.Depends(oauth2_scheme)):
    verify_token(token)
    for cart in all_carts:
        if cart["id"] == cart_id:
            return cart
    raise fastapi.exceptions.HTTPException(status_code=404, detail="Cart not found")

@app.put("/carts/{cart_id}")
async def update_cart(cart_id: int, updated_cart: Cart, token: str = fastapi.Depends(oauth2_scheme)):
    verify_token(token)
    for index, cart in enumerate(all_carts):
        if cart["id"] == cart_id:
            all_carts[index] = updated_cart.dict()
            all_carts[index]["id"] = cart_id
            return all_carts[index]
    raise fastapi.exceptions.HTTPException(status_code=404, detail="Cart not found")

@app.delete("/carts/{cart_id}")
async def delete_cart(cart_id: int, token: str = fastapi.Depends(oauth2_scheme)):
    verify_token(token)
    for index, cart in enumerate(all_carts):
        if cart["id"] == cart_id:
            del all_carts[index]
            return {"detail": "Cart deleted"}
    raise fastapi.exceptions.HTTPException(status_code=404, detail="Cart not found")