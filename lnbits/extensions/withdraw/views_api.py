from datetime import datetime
from flask import g, jsonify, request
from http import HTTPStatus
from lnurl.exceptions import InvalidUrl as LnurlInvalidUrl

from lnbits.core.crud import get_user
from lnbits.core.services import pay_invoice
from lnbits.decorators import api_check_wallet_key, api_validate_post_request
from lnbits.helpers import urlsafe_short_hash

from lnbits.extensions.withdraw import withdraw_ext
from .crud import (
    create_withdraw_link,
    get_withdraw_link,
    get_withdraw_link_by_hash,
    get_withdraw_links,
    update_withdraw_link,
    delete_withdraw_link,
)


@withdraw_ext.route("/api/v1/links", methods=["GET"])
@api_check_wallet_key("invoice")
def api_links():
    wallet_ids = [g.wallet.id]

    if "all_wallets" in request.args:
        wallet_ids = get_user(g.wallet.user).wallet_ids

    try:
        return (
            jsonify([{**link._asdict(), **{"lnurl": link.lnurl}} for link in get_withdraw_links(wallet_ids)]),
            HTTPStatus.OK,
        )
    except LnurlInvalidUrl:
        return (
            jsonify({"message": "LNURLs need to be delivered over a publically accessible `https` domain or Tor."}),
            HTTPStatus.UPGRADE_REQUIRED,
        )


@withdraw_ext.route("/api/v1/links/<link_id>", methods=["GET"])
@api_check_wallet_key("invoice")
def api_link_retrieve(link_id):
    link = get_withdraw_link(link_id, 0)

    if not link:
        return jsonify({"message": "Withdraw link does not exist."}), HTTPStatus.NOT_FOUND

    if link.wallet != g.wallet.id:
        return jsonify({"message": "Not your withdraw link."}), HTTPStatus.FORBIDDEN

    return jsonify({**link._asdict(), **{"lnurl": link.lnurl}}), HTTPStatus.OK


@withdraw_ext.route("/api/v1/links", methods=["POST"])
@withdraw_ext.route("/api/v1/links/<link_id>", methods=["PUT"])
@api_check_wallet_key("admin")
@api_validate_post_request(
    schema={
        "title": {"type": "string", "empty": False, "required": True},
        "min_withdrawable": {"type": "integer", "min": 1, "required": True},
        "max_withdrawable": {"type": "integer", "min": 1, "required": True},
        "uses": {"type": "integer", "min": 1, "required": True},
        "wait_time": {"type": "integer", "min": 1, "required": True},
        "is_unique": {"type": "boolean", "required": True},
    }
)
def api_link_create_or_update(link_id=None):
    if g.data["max_withdrawable"] < g.data["min_withdrawable"]:
        return (
            jsonify({"message": "`max_withdrawable` needs to be at least `min_withdrawable`."}),
            HTTPStatus.BAD_REQUEST,
        )

    if (g.data["max_withdrawable"] * g.data["uses"] * 1000) > g.wallet.balance_msat:
        return jsonify({"message": "Insufficient balance."}), HTTPStatus.FORBIDDEN

    if link_id:
        link = get_withdraw_link(link_id, 0)

        if not link:
            return jsonify({"message": "Withdraw link does not exist."}), HTTPStatus.NOT_FOUND

        if link.wallet != g.wallet.id:
            return jsonify({"message": "Not your withdraw link."}), HTTPStatus.FORBIDDEN

        link = update_withdraw_link(link_id, **g.data)
    else:
        link = create_withdraw_link(wallet_id=g.wallet.id, **g.data)

    return jsonify({**link._asdict(), **{"lnurl": link.lnurl}}), HTTPStatus.OK if link_id else HTTPStatus.CREATED


@withdraw_ext.route("/api/v1/links/<link_id>", methods=["DELETE"])
@api_check_wallet_key("admin")
def api_link_delete(link_id):
    link = get_withdraw_link(link_id, 0)

    if not link:
        return jsonify({"message": "Withdraw link does not exist."}), HTTPStatus.NOT_FOUND

    if link.wallet != g.wallet.id:
        return jsonify({"message": "Not your withdraw link."}), HTTPStatus.FORBIDDEN

    delete_withdraw_link(link_id)

    return "", HTTPStatus.NO_CONTENT


@withdraw_ext.route("/api/v1/lnurl/<unique_hash>", methods=["GET"])
def api_lnurl_response(unique_hash):
    link = get_withdraw_link_by_hash(unique_hash)

    if not link:
        return jsonify({"status": "ERROR", "reason": "LNURL-withdraw not found."}), HTTPStatus.OK

    link = update_withdraw_link(link.id, k1=urlsafe_short_hash())

    return jsonify(link.lnurl_response.dict()), HTTPStatus.OK


@withdraw_ext.route("/api/v1/lnurl/cb/<unique_hash>", methods=["GET"])
def api_lnurl_callback(unique_hash):
    link = get_withdraw_link_by_hash(unique_hash)
    k1 = request.args.get("k1", type=str)
    payment_request = request.args.get("pr", type=str)
    now = int(datetime.now().timestamp())

    if not link:
        return jsonify({"status": "ERROR", "reason": "LNURL-withdraw not found."}), HTTPStatus.OK

    if link.is_spent:
        return jsonify({"status": "ERROR", "reason": "Withdraw is spent."}), HTTPStatus.OK

    if link.k1 != k1:
        return jsonify({"status": "ERROR", "reason": "Bad request."}), HTTPStatus.OK

    if now < link.open_time:
        return jsonify({"status": "ERROR", "reason": f"Wait {link.open_time - now} seconds."}), HTTPStatus.OK

    try:
        pay_invoice(wallet_id=link.wallet, bolt11=payment_request, max_sat=link.max_withdrawable)

        changes = {
            "used": link.used + 1,
            "open_time": link.wait_time + now,
        }

        if link.is_unique:
            hashes = link.unique_hash.split(",")
            hashes.remove(unique_hash)
            changes["unique_hash"] = ','.join(hashes)
            
        update_withdraw_link(link.id, **changes)

    except ValueError as e:
        return jsonify({"status": "ERROR", "reason": str(e)}), HTTPStatus.OK
    except PermissionError:
        return jsonify({"status": "ERROR", "reason": "Withdraw link is empty."}), HTTPStatus.OK
    except Exception as e:
        return jsonify({"status": "ERROR", "reason": str(e)}), HTTPStatus.OK

    return jsonify({"status": "OK"}), HTTPStatus.OK
