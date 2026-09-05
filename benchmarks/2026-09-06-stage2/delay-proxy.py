import asyncio, sys
DELAY=float(sys.argv[1])/1000
TARGET=sys.argv[2]
async def direction(reader, writer):
    queue=asyncio.Queue(maxsize=128)
    async def read():
        while True:
            data=await reader.read(65536)
            await queue.put((asyncio.get_running_loop().time()+DELAY,data))
            if not data: break
    async def write():
        while True:
            due,data=await queue.get()
            await asyncio.sleep(max(0,due-asyncio.get_running_loop().time()))
            if not data:
                writer.write_eof()
                await writer.drain()
                return
            writer.write(data)
            await writer.drain()
    tasks=[asyncio.create_task(read()),asyncio.create_task(write())]
    try: await asyncio.gather(*tasks)
    finally:
        for t in tasks:t.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
async def connection(reader,writer):
    remote=None;tasks=[]
    try:
        rr,remote=await asyncio.open_connection(TARGET,8443)
        tasks=[asyncio.create_task(direction(reader,remote)),asyncio.create_task(direction(rr,writer))]
        await asyncio.gather(*tasks)
    except (ConnectionError,OSError):pass
    finally:
        for t in tasks:t.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        writer.close()
        if remote:remote.close()
async def main():
    server=await asyncio.start_server(connection,'0.0.0.0',9443)
    async with server:await server.serve_forever()
asyncio.run(main())
