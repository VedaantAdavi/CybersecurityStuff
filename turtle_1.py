import turtle

#This creates a turtle that pyhton can draw with 
a=turtle.Turtle() 

# The rest of the functions configure the turtles speed, color and visibility
a.color('green') 
a.speed(0) 
a.hideturtle() 

#This creates the canvas that the turtle will draw on and sets the color
s=turtle.Screen()
s.bgcolor('black')

#Makes the turtle draw lines for values between 0 and 199
for x in range(200):
    a.forward(x)
    a.left(x-1)
turtle.done()