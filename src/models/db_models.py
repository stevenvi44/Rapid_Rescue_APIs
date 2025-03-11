import sqlalchemy as _sql
import sqlalchemy.orm as _orm
from src import database as _database

class User(_database.Base):
    __tablename__ = "users"
    
    user_id = _sql.Column(_sql.Integer, primary_key=True, autoincrement=True)
    username = _sql.Column(_sql.String(100), nullable=False)
    email = _sql.Column(_sql.String(255), unique=True, index=True, nullable=False)
    phone_number = _sql.Column(_sql.String(13), nullable=False)
    password = _sql.Column(_sql.String(50), nullable=False)
    location = _sql.Column(_sql.String(255), nullable=False)
    is_active = _sql.Column(_sql.Boolean, default=True)
    role = _sql.Column(_sql.String(50), nullable=False)
    reset_token = _sql.Column(_sql.String(255), nullable=True)
    
    orders = _orm.relationship("Order", back_populates="user")
    user_cars = _orm.relationship("UserCar", back_populates="user")
    service_requests = _orm.relationship("ServiceRequest", back_populates="user")

class Car(_database.Base):
    __tablename__ = "cars"
    
    car_id = _sql.Column(_sql.Integer, primary_key=True, autoincrement=True)
    make = _sql.Column(_sql.String(50), nullable=False)
    model = _sql.Column(_sql.String(50), nullable=False)
    
    user_cars = _orm.relationship("UserCar", back_populates="car")
    cars_spare_parts = _orm.relationship("CarsSpareParts", back_populates="car")

class UserCar(_database.Base):
    __tablename__ = "user_cars"
    
    user_car_id = _sql.Column(_sql.Integer, primary_key=True, autoincrement=True)
    user_id = _sql.Column(_sql.Integer, _sql.ForeignKey("users.user_id"), nullable=False)
    car_id = _sql.Column(_sql.Integer, _sql.ForeignKey("cars.car_id"), nullable=False)
    ownership_type = _sql.Column(_sql.String(20), nullable=True)
    year = _sql.Column(_sql.Integer, nullable=False)
    license_plate = _sql.Column(_sql.String(20), nullable=True, unique=True)
    current_mileage = _sql.Column(_sql.String(20), nullable=True)
    
    user = _orm.relationship("User", back_populates="user_cars")
    car = _orm.relationship("Car", back_populates="user_cars")
    orders = _orm.relationship("Order", back_populates="user_car")  
    service_requests = _orm.relationship("ServiceRequest", back_populates="user_car")
    ai_preventive_maintenance = _orm.relationship("AIPreventiveMaintenance", back_populates="user_car")

class Order(_database.Base):
    __tablename__ = "orders"
    
    order_id = _sql.Column(_sql.Integer, primary_key=True, autoincrement=True)
    user_id = _sql.Column(_sql.Integer, _sql.ForeignKey("users.user_id"), nullable=False)
    user_car_id = _sql.Column(_sql.Integer, _sql.ForeignKey("user_cars.user_car_id"), nullable=False)
    order_status = _sql.Column(_sql.String(255), nullable=False)
    order_date = _sql.Column(_sql.DateTime, nullable=False)
    total_cost = _sql.Column(_sql.Float, nullable=False)
    
    user = _orm.relationship("User", back_populates="orders")
    user_car = _orm.relationship("UserCar", back_populates="orders")
    order_services = _orm.relationship("OrderService", back_populates="order")
    order_parts = _orm.relationship("OrderPart", back_populates="order")
    transactions = _orm.relationship("Transaction", back_populates="order")

class OrderService(_database.Base):
    __tablename__ = "order_services" 
    
    order_service_id = _sql.Column(_sql.Integer, primary_key=True, autoincrement=True)
    order_id = _sql.Column(_sql.Integer, _sql.ForeignKey("orders.order_id"), nullable=False)
    request_id = _sql.Column(_sql.Integer, _sql.ForeignKey("service_requests.request_id"), nullable=False)
    cost = _sql.Column(_sql.Float, nullable=False)
    
    order = _orm.relationship("Order", back_populates="order_services")
    request = _orm.relationship("ServiceRequest", back_populates="order_services")

class OrderPart(_database.Base):
    __tablename__ = "order_parts"
    
    order_part_id = _sql.Column(_sql.Integer, primary_key=True, autoincrement=True)
    order_id = _sql.Column(_sql.Integer, _sql.ForeignKey("orders.order_id"), nullable=False)
    part_id = _sql.Column(_sql.Integer, _sql.ForeignKey("spare_parts.part_id"), nullable=False)
    quantity = _sql.Column(_sql.Integer, nullable=False)
    
    order = _orm.relationship("Order", back_populates="order_parts")
    part = _orm.relationship("SparePart", back_populates="order_parts")

class SparePart(_database.Base):
    __tablename__ = "spare_parts"
    
    part_id = _sql.Column(_sql.Integer, primary_key=True, autoincrement=True)
    service_provider_id = _sql.Column(_sql.Integer, _sql.ForeignKey("service_providers.service_provider_id"), nullable=False)
    name = _sql.Column(_sql.String(100), nullable=False)
    description = _sql.Column(_sql.Text, nullable=False)
    price = _sql.Column(_sql.Float, nullable=False)
    availability_status = _sql.Column(_sql.String(50), nullable=False)
    
    service_provider = _orm.relationship("ServiceProvider", back_populates="spare_parts")
    order_parts = _orm.relationship("OrderPart", back_populates="part")
    cars_spare_parts = _orm.relationship("CarsSpareParts", back_populates="spare_part") 

class ServiceProvider(_database.Base):
    __tablename__ = "service_providers"
    
    service_provider_id = _sql.Column(_sql.Integer, primary_key=True, autoincrement=True)
    name = _sql.Column(_sql.String(100), nullable=False)
    email = _sql.Column(_sql.String(255), unique=True, nullable=False)
    phone_number = _sql.Column(_sql.String(13), nullable=False)
    location = _sql.Column(_sql.String(255), nullable=False)
    contact_person = _sql.Column(_sql.String(100), nullable=False)
    other_details = _sql.Column(_sql.Text, nullable=True)
    
    service_requests = _orm.relationship("ServiceRequest", back_populates="service_provider")
    spare_parts = _orm.relationship("SparePart", back_populates="service_provider")

class ServiceRequest(_database.Base):
    __tablename__ = "service_requests"
    
    request_id = _sql.Column(_sql.Integer, primary_key=True, autoincrement=True)
    user_id = _sql.Column(_sql.Integer, _sql.ForeignKey("users.user_id"), nullable=False)
    user_car_id = _sql.Column(_sql.Integer, _sql.ForeignKey("user_cars.user_car_id"), nullable=False)
    service_provider_id = _sql.Column(_sql.Integer, _sql.ForeignKey("service_providers.service_provider_id"), nullable=False)
    service_type = _sql.Column(_sql.String(50), nullable=False)
    status = _sql.Column(_sql.String(50), nullable=False)
    cost = _sql.Column(_sql.Float, nullable=False)
    
    user = _orm.relationship("User", back_populates="service_requests")
    user_car = _orm.relationship("UserCar", back_populates="service_requests")
    service_provider = _orm.relationship("ServiceProvider", back_populates="service_requests")
    order_services = _orm.relationship("OrderService", back_populates="request")
    ai_preventive_maintenance = _orm.relationship("AIPreventiveMaintenance", back_populates="request")

class AIPreventiveMaintenance(_database.Base):
    __tablename__ = "ai_preventive_maintenance"
    
    maintenance_id = _sql.Column(_sql.Integer, primary_key=True, autoincrement=True)
    user_car_id = _sql.Column(_sql.Integer, _sql.ForeignKey("user_cars.user_car_id"), nullable=False)
    request_id = _sql.Column(_sql.Integer, _sql.ForeignKey("service_requests.request_id"), nullable=False)
    predicted_issue = _sql.Column(_sql.String(255), nullable=True)
    recommendation = _sql.Column(_sql.String(255), nullable=True)
    last_checkup_date = _sql.Column(_sql.Date, nullable=True)
    next_checkup_date = _sql.Column(_sql.Date, nullable=True)

    user_car = _orm.relationship("UserCar", back_populates="ai_preventive_maintenance")
    request = _orm.relationship("ServiceRequest", back_populates="ai_preventive_maintenance")

class Transaction(_database.Base):
    __tablename__ = "transactions"
    
    transaction_id = _sql.Column(_sql.Integer, primary_key=True, autoincrement=True)
    order_id = _sql.Column(_sql.Integer, _sql.ForeignKey("orders.order_id"), nullable=False)
    total_paid_amount = _sql.Column(_sql.Integer, nullable=False)
    payment_method = _sql.Column(_sql.String(100), nullable=False)
    payment_status = _sql.Column(_sql.String(100), nullable=False)
    
    order = _orm.relationship("Order", back_populates="transactions")

class CarsSpareParts(_database.Base):
    __tablename__ = "cars_spare_parts"
    
    car_id = _sql.Column(_sql.Integer, _sql.ForeignKey("cars.car_id"), primary_key=True)
    part_id = _sql.Column(_sql.Integer, _sql.ForeignKey("spare_parts.part_id"), primary_key=True)
    
    car = _orm.relationship("Car", back_populates="cars_spare_parts")
    spare_part = _orm.relationship("SparePart", back_populates="cars_spare_parts") 
