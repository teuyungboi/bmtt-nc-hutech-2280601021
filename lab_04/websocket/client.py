import tornado.ioloop
import tornado.websocket
import functools

class WebSocketClient:
    def __init__(self, io_loop):
        self.connection = None
        self.io_loop = io_loop

    def start(self):
        self.connect_and_read()

    def stop(self):
        if self.connection:
            self.connection.close()
        self.io_loop.stop()

    def connect_and_read(self):
        print("Đang kết nối đến WebSocket server...")

        future = tornado.websocket.websocket_connect("ws://localhost:8888/websocket/")
        future.add_done_callback(self.maybe_retry_connection)

    def maybe_retry_connection(self, future) -> None:
        try:
            self.connection = future.result()  # Sửa lỗi chính tả
            print("Đã kết nối thành công!")
            self.read_message()
        except Exception as e:
            print(f"Không thể kết nối lại, thử lại sau 3 giây... Lỗi: {e}")
            self.io_loop.call_later(3, self.connect_and_read)

    def read_message(self):
        if self.connection:
            self.connection.read_message(callback=self.on_message)

    def on_message(self, message):
        if message is None:
            print("Mất kết nối, đang thử kết nối lại...")
            self.connect_and_read()
            return

        print(f"Received word from server: {message}")
        self.read_message()

def main():
    io_loop = tornado.ioloop.IOLoop.current()

    client = WebSocketClient(io_loop)
    io_loop.add_callback(client.start)

    try:
        io_loop.start()
    except KeyboardInterrupt:
        print("Đang đóng kết nối...")
        client.stop()

if __name__ == "__main__":
    main()