import time

def main():
    print("worker: started", flush=True)
    while True:
        time.sleep(5)
        print("worker: heartbeat", flush=True)

if __name__ == "__main__":
    main()
