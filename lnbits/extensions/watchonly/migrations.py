async def m001_initial(db):
    """
    Initial wallet table.
    """
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS wallets (
            id TEXT NOT NULL PRIMARY KEY,
            user TEXT,
            masterpub TEXT NOT NULL,
            title TEXT NOT NULL,
            address_no INTEGER NOT NULL DEFAULT 0,
            balance INTEGER NOT NULL
        );
    """
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS addresses (
            address TEXT NOT NULL PRIMARY KEY,
            wallet TEXT NOT NULL,
            amount INTEGER NOT NULL
        );
    """
    )
    
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS mempool (
            user TEXT NOT NULL,
            endpoint TEXT NOT NULL 
        );
    """
    )