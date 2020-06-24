from flask import g, abort, render_template
from http import HTTPStatus

from lnbits.decorators import check_user_exists, validate_uuids

from lnbits.extensions.withdraw import withdraw_ext
from .crud import get_withdraw_link


@withdraw_ext.route("/")
@validate_uuids(["usr"], required=True)
@check_user_exists()
def index():
    return render_template("withdraw/index.html", user=g.user)


@withdraw_ext.route("/<link_id>")
def display(link_id):
    link = get_withdraw_link(link_id, 0) or abort(HTTPStatus.NOT_FOUND, "Withdraw link does not exist.")

    return render_template("withdraw/display.html", link=link)


@withdraw_ext.route("/print/<link_id>")
def print_qr(link_id):
    links = []
    link = get_withdraw_link(link_id, 0) or abort(HTTPStatus.NOT_FOUND, "Withdraw link does not exist.")
    if link.is_unique == True:
        for i in range(link.uses):
            links.append(get_withdraw_link(link_id, i))

    return render_template("withdraw/print_qr.html", link=link, unique=True, links=links)
