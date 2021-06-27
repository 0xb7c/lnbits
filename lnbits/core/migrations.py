from sqlalchemy.exc import OperationalError  # type: ignore
from os import getenv
from lnbits.helpers import urlsafe_short_hash
from .crud import create_account, get_user


async def m000_create_migrations_table(db):
    await db.execute(
        """
    CREATE TABLE dbversions (
        db TEXT PRIMARY KEY,
        version INT NOT NULL
    )
    """
    )


async def m001_initial(db):
    """
    Initial LNbits tables.
    """
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            email TEXT,
            pass TEXT
        );
    """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS extensions (
            user TEXT NOT NULL,
            extension TEXT NOT NULL,
            active BOOLEAN DEFAULT 0,

            UNIQUE (user, extension)
        );
    """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS wallets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            user TEXT NOT NULL,
            adminkey TEXT NOT NULL,
            inkey TEXT
        );
    """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS apipayments (
            payhash TEXT NOT NULL,
            amount INTEGER NOT NULL,
            fee INTEGER NOT NULL DEFAULT 0,
            wallet TEXT NOT NULL,
            pending BOOLEAN NOT NULL,
            memo TEXT,
            time TIMESTAMP NOT NULL DEFAULT (strftime('%s', 'now')),

            UNIQUE (wallet, payhash)
        );
    """
    )

    await db.execute(
        """
        CREATE VIEW IF NOT EXISTS balances AS
        SELECT wallet, COALESCE(SUM(s), 0) AS balance FROM (
            SELECT wallet, SUM(amount) AS s  -- incoming
            FROM apipayments
            WHERE amount > 0 AND pending = 0  -- don't sum pending
            GROUP BY wallet
            UNION ALL
            SELECT wallet, SUM(amount + fee) AS s  -- outgoing, sum fees
            FROM apipayments
            WHERE amount < 0  -- do sum pending
            GROUP BY wallet
        )
        GROUP BY wallet;
    """
    )


async def m002_add_fields_to_apipayments(db):
    """
    Adding fields to apipayments for better accounting,
    and renaming payhash to checking_id since that is what it really is.
    """
    try:
        await db.execute("ALTER TABLE apipayments RENAME COLUMN payhash TO checking_id")
        await db.execute("ALTER TABLE apipayments ADD COLUMN hash TEXT")
        await db.execute("CREATE INDEX by_hash ON apipayments (hash)")
        await db.execute("ALTER TABLE apipayments ADD COLUMN preimage TEXT")
        await db.execute("ALTER TABLE apipayments ADD COLUMN bolt11 TEXT")
        await db.execute("ALTER TABLE apipayments ADD COLUMN extra TEXT")

        import json

        rows = await (await db.execute("SELECT * FROM apipayments")).fetchall()
        for row in rows:
            if not row["memo"] or not row["memo"].startswith("#"):
                continue

            for ext in ["withdraw", "events", "lnticket", "paywall", "tpos"]:
                prefix = "#" + ext + " "
                if row["memo"].startswith(prefix):
                    new = row["memo"][len(prefix) :]
                    await db.execute(
                        """
                        UPDATE apipayments SET extra = ?, memo = ?
                        WHERE checking_id = ? AND memo = ?
                        """,
                        (
                            json.dumps({"tag": ext}),
                            new,
                            row["checking_id"],
                            row["memo"],
                        ),
                    )
                    break
    except OperationalError:
        # this is necessary now because it may be the case that this migration will
        # run twice in some environments.
        # catching errors like this won't be necessary in anymore now that we
        # keep track of db versions so no migration ever runs twice.
        pass


async def m003_add_invoice_webhook(db):
    """
    Special column for webhook endpoints that can be assigned
    to each different invoice.
    """

    await db.execute("ALTER TABLE apipayments ADD COLUMN webhook TEXT")
    await db.execute("ALTER TABLE apipayments ADD COLUMN webhook_status TEXT")


async def m004_ensure_fees_are_always_negative(db):
    """
    Use abs() so wallet backends don't have to care about the sign of the fees.
    """

    await db.execute("DROP VIEW balances")

    await db.execute(
        """
        CREATE VIEW IF NOT EXISTS balances AS
        SELECT wallet, COALESCE(SUM(s), 0) AS balance FROM (
            SELECT wallet, SUM(amount) AS s  -- incoming
            FROM apipayments
            WHERE amount > 0 AND pending = 0  -- don't sum pending
            GROUP BY wallet
            UNION ALL
            SELECT wallet, SUM(amount - abs(fee)) AS s  -- outgoing, sum fees
            FROM apipayments
            WHERE amount < 0  -- do sum pending
            GROUP BY wallet
        )
        GROUP BY wallet;
    """
    )


async def m005_balance_check_balance_notify(db):
    """
    Keep track of balanceCheck-enabled lnurl-withdrawals to be consumed by an LNbits wallet and of balanceNotify URLs supplied by users to empty their wallets.
    """

    await db.execute(
        """
        CREATE TABLE balance_check (
          wallet INTEGER NOT NULL REFERENCES wallets (id),
          service TEXT NOT NULL,
          url TEXT NOT NULL,

          UNIQUE(wallet, service)
        );
    """
    )

    await db.execute(
        """
        CREATE TABLE balance_notify (
          wallet INTEGER NOT NULL REFERENCES wallets (id),
          url TEXT NOT NULL,

          UNIQUE(wallet, url)
        );
    """
    )


def m003_create_admin_table(db):
    user = None
    site_title = None
    tagline = ""
    primary_color = "#673ab7"
    secondary_color = "#9c27b0"
    allowed_users = None
    default_wallet_name = None
    data_folder = None
    disabled_ext = None
    force_https = True
    service_fee = 0
    funding_source = ''

    if getenv("LNBITS_SITE_TITLE"):
        site_title = getenv("LNBITS_SITE_TITLE")

    if getenv("LNBITS_TAGLINE"):
        tagline = getenv("LNBITS_TAGLINE")

    if getenv("LNBITS_ALLOWED_USERS"):
        allowed_users = getenv("LNBITS_ALLOWED_USERS")

    if getenv("LNBITS_DEFAULT_WALLET_NAME"):
        default_wallet_name = getenv("LNBITS_DEFAULT_WALLET_NAME")

    if getenv("LNBITS_DATA_FOLDER"):
        data_folder = getenv("LNBITS_DATA_FOLDER")

    if getenv("LNBITS_DISABLED_EXTENSIONS"):
        disabled_ext = getenv("LNBITS_DISABLED_EXTENSIONS")

    if getenv("LNBITS_FORCE_HTTPS"):
        force_https = getenv("LNBITS_FORCE_HTTPS")

    if getenv("LNBITS_SERVICE_FEE"):
        service_fee = getenv("LNBITS_SERVICE_FEE")

    if getenv("LNBITS_BACKEND_WALLET_CLASS"):
        funding_source = getenv("LNBITS_BACKEND_WALLET_CLASS")

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS admin (
            user TEXT,
            site_title TEXT NOT NULL,
            tagline TEXT,
            primary_color TEXT NOT NULL,
            secondary_color TEXT NOT NULL,
            allowed_users TEXT,
            default_wallet_name TEXT,
            data_folder TEXT,
            disabled_ext TEXT,
            force_https BOOLEAN NOT NULL,
            service_fee INT NOT NULL,
            funding_source TEXT
        );
    """
    )
    db.execute(
        """
        INSERT INTO admin (user, site_title, tagline, primary_color, secondary_color, allowed_users, default_wallet_name, data_folder, disabled_ext, force_https, service_fee, funding_source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user,
            site_title,
            tagline,
            primary_color,
            secondary_color,
            allowed_users,
            default_wallet_name,
            data_folder,
            disabled_ext,
            force_https,
            service_fee,
            funding_source,
        ),
    )


def m003_create_funding_table(db):

    # Make the funding table,  if it does not already exist

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS funding (
            id TEXT PRIMARY KEY,
            backend_wallet TEXT,
            endpoint TEXT,
            port INT,
            read_key TEXT,
            invoice_key TEXT,
            admin_key TEXT,
            cert TEXT,
            balance int
        );
    """
    )

    # Get the funding source rows back if they exist

    CLightningWallet = db.fetchall("SELECT * FROM funding WHERE backend_wallet = ?", ("CLightningWallet",))
    LnbitsWallet = db.fetchall("SELECT * FROM funding WHERE backend_wallet = ?", ("LnbitsWallet",))
    LndWallet = db.fetchall("SELECT * FROM funding WHERE backend_wallet = ?", ("LndWallet",))
    LndRestWallet = db.fetchall("SELECT * FROM funding WHERE backend_wallet = ?", ("LndRestWallet",))
    LNPayWallet = db.fetchall("SELECT * FROM funding WHERE backend_wallet = ?", ("LNPayWallet",))
    LntxbotWallet = db.fetchall("SELECT * FROM funding WHERE backend_wallet = ?", ("LntxbotWallet",))
    OpenNodeWallet = db.fetchall("SELECT * FROM funding WHERE backend_wallet = ?", ("OpenNodeWallet",))


    db.execute(
        """
        INSERT INTO funding (id, backend_wallet, endpoint)
        VALUES (?, ?, ?)
        """,
        (urlsafe_short_hash(), "CLightningWallet", getenv("CLIGHTNING_RPC")),
    )

    db.execute(
        """
        INSERT INTO funding (id, backend_wallet, endpoint, invoice_key, admin_key)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            urlsafe_short_hash(),
            "LnbitsWallet",
            getenv("LNBITS_ENDPOINT"),
            getenv("LNBITS_INVOICE_MACAROON"),
            getenv("LNBITS_ADMIN_MACAROON"),
        ),
    )

    db.execute(
        """
        INSERT INTO funding (id, backend_wallet, endpoint, port, read_key, invoice_key, admin_key, cert)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            urlsafe_short_hash(),
            "LndWallet",
            getenv("LND_GRPC_ENDPOINT"),
            getenv("LND_GRPC_PORT"),
            getenv("LND_READ_MACAROON"),
            getenv("LND_INVOICE_MACAROON"),
            getenv("LND_ADMIN_MACAROON"),
            getenv("LND_CERT"),
        ),
    )


    db.execute(
        """
        INSERT INTO funding (id, backend_wallet, endpoint, read_key, invoice_key, admin_key, cert)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            urlsafe_short_hash(),
            "LndRestWallet",
            getenv("LND_REST_ENDPOINT"),
            getenv("LND_REST_READ_MACAROON"),
            getenv("LND_REST_INVOICE_MACAROON"),
            getenv("LND_REST_ADMIN_MACAROON"),
            getenv("LND_REST_CERT"),
        ),
    )

    db.execute(
        """
        INSERT INTO funding (id, backend_wallet, endpoint, read_key, invoice_key, admin_key, cert)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            urlsafe_short_hash(),
            "LNPayWallet",
            getenv("LNPAY_API_ENDPOINT"),
            getenv("LNPAY_READ_KEY"),
            getenv("LNPAY_INVOICE_KEY"),
            getenv("LNPAY_ADMIN_KEY"),
            getenv("LNPAY_API_KEY"),
        ),
    )


    db.execute(
        """
        INSERT INTO funding (id, backend_wallet, endpoint, invoice_key, admin_key)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            urlsafe_short_hash(),
            "LntxbotWallet",
            getenv("LNTXBOT_API_ENDPOINT"),
            getenv("LNTXBOT_INVOICE_KEY"),
            getenv("LNTXBOT_ADMIN_KEY"),
        ),
    )


    db.execute(
        """
        INSERT INTO funding (id, backend_wallet, endpoint, invoice_key, admin_key)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            urlsafe_short_hash(),
            "OpenNodeWallet",
            getenv("OPENNODE_API_ENDPOINT"),
            getenv("OPENNODE_INVOICE_KEY"),
            getenv("OPENNODE_ADMIN_KEY"),
        ),
    )