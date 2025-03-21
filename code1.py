while True:
    print("1.SUM")
    print("2.SUB")
    print("3.MUL")
    print("4.DIV")
    print("5.EXIT")
    cho=int(input("enter the choice"))
    match cho:
        case 1:
            a=int(input("enter the number a:"))
            b=int(input("enetr the number b:"))
            c=a+b
            print("the sum:",c)
        case 2:
            a=int(input("enter the number a:"))
            b=int(input("enetr the number b:"))
            c=a-b
            print("the subtraction:",c)
        case 3:
            a=int(input("enter the number a:"))
            b=int(input("enetr the number b:"))
            c=a*b
            print("the product:",c)
        case 4:
            a=int(input("enter the number a:"))
            b=int(input("enetr the number b:"))
            c=a/b
            print("the qucient:",c)
        case 5:
            break
        case _:
            print("invalid input")
