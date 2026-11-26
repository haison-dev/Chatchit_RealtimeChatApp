/** A small red counter on the corner of an icon; nothing when the count is zero. The parent must be `relative`. */
const CountBadge = ({ count }: { count: number }) => {
  if (count <= 0) return null;
  return (
    <span className="absolute -right-1.5 -top-1 min-w-4 rounded-full bg-destructive px-1 text-center text-[10px] leading-4 text-white">
      {count > 9 ? "9+" : count}
    </span>
  );
};

export default CountBadge;
