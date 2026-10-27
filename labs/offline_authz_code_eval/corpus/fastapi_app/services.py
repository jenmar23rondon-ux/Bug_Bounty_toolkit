"""Synthetic service layer: ownership-scoped query."""


class _Query:
    def filter_by(self, **kwargs: int) -> "_Query":
        return self

    def first(self) -> dict[str, int]:
        return {}


def get_order_for_user(order_id: int, user: dict[str, int]) -> dict[str, int]:
    return _Query().filter_by(id=order_id, owner_id=user["id"]).first()
