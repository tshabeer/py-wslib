# py-wslib - Python WebSocket Library

----


## Examples

### Client

    import time    
    from wslib import WebSocket, WebSocketHandler
    
    class HelloHandler(WebSocketHandler):
        
        def onopen(self, protocol):
            print "open"
            self.websocket.send('Hello World!')
        
        def onmessage(self, message):
            print "received message:", message
        
        def onclose(self):
            print "close"
    
    if __name__ == '__main__':
        ws = WebSocket('ws://127.0.0.1:8080/', HelloHandler())
        ws.connect()
        time.sleep(5)
        ws.close()


### Server
    from wslib import WebSocketServer, WebSocketRequestHandler
    
    class EchoHandler(WebSocketRequestHandler):
        
        def onrequest(self, request):
            print "received request"
            request.accept()
    
        def onopen(self, protocol):
            print "open"
    
        def onmessage(self, message):
            print "new message:", message
            self.websocket.send(message)
    
        def onclose(self):
            print "closed"

    if __name__ == '__main__':
        websocket = WebSocketServer('127.0.0.1', 8080, EchoHandler())
        websocket.serve_forever()
