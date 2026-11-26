import { useState } from "react";
import { formatNumber, shortDay } from "@/lib/admin";
import { cn } from "@/lib/utils";
import type { DailyCount } from "@/types/admin";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Skeleton } from "../ui/skeleton";

const CHART_HEIGHT = 160;

/** Số tròn cho trục y: 0, một vạch giữa và đỉnh. */
const niceMax = (value: number) => {
  if (value <= 4) return 4;
  const step = 10 ** Math.floor(Math.log10(value));
  return Math.ceil(value / step) * step;
};

/**
 * Số tài khoản mới mỗi ngày. Chỉ một chuỗi số liệu nên dùng một màu, không cần chú thích (tiêu đề đã nói rõ).
 * Mỗi cột hiện giá trị khi rê chuột hoặc focus bằng bàn phím; cùng số liệu có trong bảng bên dưới.
 */
const SignupChart = ({ data }: { data: DailyCount[] | null }) => {
  const [active, setActive] = useState<number | null>(null);

  if (!data) {
    return (
      <Card>
        <CardHeader><CardTitle className="text-base">Người dùng mới theo ngày</CardTitle></CardHeader>
        <CardContent><Skeleton className="h-44 w-full" /></CardContent>
      </Card>
    );
  }

  const total = data.reduce((sum, day) => sum + day.count, 0);
  const max = niceMax(Math.max(...data.map((day) => day.count), 0));
  const ticks = [max, max / 2, 0];
  const shown = active !== null ? data[active] : null;

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-baseline justify-between gap-2">
        <div>
          <CardTitle className="text-base">Người dùng mới theo ngày</CardTitle>
          <p className="mt-1 text-sm text-muted-foreground">{data.length} ngày qua · tổng {formatNumber(total)} tài khoản</p>
        </div>
        {/* Tooltip đặt cố định ở đây để không che cột và không tràn khỏi màn hình hẹp. */}
        <p className="min-h-5 text-sm tabular-nums text-foreground" aria-live="polite">
          {shown ? <><span className="text-muted-foreground">{shortDay(shown.date)}:</span> <strong>{formatNumber(shown.count)}</strong> người đăng ký</> : null}
        </p>
      </CardHeader>
      <CardContent>
        <div className="flex gap-2">
          {/* trục y */}
          <div className="flex shrink-0 flex-col justify-between text-right text-[11px] tabular-nums text-muted-foreground" style={{ height: CHART_HEIGHT }} aria-hidden="true">
            {ticks.map((tick) => <span key={tick} className="-my-1.5">{formatNumber(tick)}</span>)}
          </div>

          <div className="relative min-w-0 flex-1">
            {/* đường lưới mờ */}
            <div className="pointer-events-none absolute inset-x-0 top-0 flex flex-col justify-between" style={{ height: CHART_HEIGHT }} aria-hidden="true">
              {ticks.map((tick) => <span key={tick} className="border-t border-border/60" />)}
            </div>

            <ol
              className="relative flex items-end gap-[2px]"
              style={{ height: CHART_HEIGHT }}
              aria-label="Biểu đồ người dùng mới theo ngày"
              onMouseLeave={() => setActive(null)}
            >
              {data.map((day, index) => (
                <li key={day.date} className="flex h-full min-w-0 flex-1 items-end">
                  {/* vùng bấm là cả cột, lớn hơn phần cột tô màu */}
                  <button
                    type="button"
                    className="group flex h-full w-full items-end rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    aria-label={`${shortDay(day.date)}: ${day.count} người đăng ký`}
                    onMouseEnter={() => setActive(index)}
                    onFocus={() => setActive(index)}
                    onBlur={() => setActive(null)}
                  >
                    <span
                      className={cn(
                        "block w-full rounded-t-[4px] bg-primary transition-opacity",
                        active !== null && active !== index && "opacity-40",
                      )}
                      style={{ height: day.count ? `${Math.max((day.count / max) * 100, 2)}%` : 0 }}
                    />
                  </button>
                </li>
              ))}
            </ol>
            <div className="mt-1 flex justify-between text-[11px] text-muted-foreground" aria-hidden="true">
              <span>{shortDay(data[0].date)}</span>
              <span>{shortDay(data[Math.floor(data.length / 2)].date)}</span>
              <span>Hôm nay</span>
            </div>
          </div>
        </div>

        <details className="mt-4 text-sm">
          <summary className="cursor-pointer text-muted-foreground hover:text-foreground">Xem bảng số liệu</summary>
          <div className="mt-2 max-h-56 overflow-y-auto rounded-md border">
            <table className="w-full text-left">
              <thead className="sticky top-0 bg-muted text-xs text-muted-foreground">
                <tr><th className="px-3 py-2 font-medium">Ngày</th><th className="px-3 py-2 text-right font-medium">Người đăng ký</th></tr>
              </thead>
              <tbody>
                {[...data].reverse().map((day) => (
                  <tr key={day.date} className="border-t">
                    <td className="px-3 py-1.5">{shortDay(day.date)}</td>
                    <td className="px-3 py-1.5 text-right tabular-nums">{formatNumber(day.count)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      </CardContent>
    </Card>
  );
};

export default SignupChart;
