import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
import { getApiErrorMessage } from "@/lib/apiError";
import {
  AVATAR_URL_MAX_LENGTH,
  BIO_MAX_LENGTH,
  DISPLAY_NAME_MAX_LENGTH,
  PHONE_PATTERN,
  isHttpsUrl,
  sanitizeText,
} from "@/lib/sanitize";
import { useAuthStore } from "@/stores/useAuthStore";
import type { UserProfile } from "@/types/user";
import UserAvatar from "../chat/UserAvatar";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import { RequiredMark } from "../ui/required-mark";
import { Textarea } from "../ui/textarea";

// Mirrors the rules in backend userController.updateMe; the server validates again.
const profileSchema = z.object({
  displayName: z.string()
    .transform((value) => sanitizeText(value))
    .pipe(z.string().min(1, "Vui lòng nhập tên hiển thị").max(DISPLAY_NAME_MAX_LENGTH, `Tối đa ${DISPLAY_NAME_MAX_LENGTH} ký tự`)),
  bio: z.string()
    .transform((value) => sanitizeText(value, { multiline: true }))
    .pipe(z.string().max(BIO_MAX_LENGTH, `Tối đa ${BIO_MAX_LENGTH} ký tự`)),
  phone: z.string()
    .transform((value) => sanitizeText(value))
    .pipe(z.string().refine((value) => value === "" || PHONE_PATTERN.test(value), "Số điện thoại không hợp lệ")),
  avatarUrl: z.string()
    .trim()
    .max(AVATAR_URL_MAX_LENGTH, `Tối đa ${AVATAR_URL_MAX_LENGTH} ký tự`)
    .refine((value) => value === "" || isHttpsUrl(value), "Đường dẫn ảnh phải bắt đầu bằng https://"),
});

type ProfileFormValues = z.input<typeof profileSchema>;
type ProfileFormOutput = z.output<typeof profileSchema>;

interface ProfileEditFormProps {
  profile: UserProfile;
  onCancel: () => void;
  onSaved: () => void;
}

const ProfileEditForm = ({ profile, onCancel, onSaved }: ProfileEditFormProps) => {
  const updateProfile = useAuthStore((state) => state.updateProfile);
  const {
    register,
    handleSubmit,
    control,
    formState: { errors, isSubmitting },
  } = useForm<ProfileFormValues, unknown, ProfileFormOutput>({
    resolver: zodResolver(profileSchema),
    defaultValues: {
      displayName: profile.displayName,
      bio: profile.bio ?? "",
      phone: profile.phone ?? "",
      avatarUrl: profile.avatarUrl ?? "",
    },
  });

  const avatarUrl = useWatch({ control, name: "avatarUrl" }) ?? "";
  const displayName = useWatch({ control, name: "displayName" }) ?? "";
  const bio = useWatch({ control, name: "bio" }) ?? "";
  const previewUrl = isHttpsUrl(avatarUrl.trim()) ? avatarUrl.trim() : undefined;

  const onSubmit = async (values: ProfileFormOutput) => {
    try {
      await updateProfile(values);
      toast.success("Đã cập nhật hồ sơ.");
      onSaved();
    } catch (error) {
      toast.error(getApiErrorMessage(error, "Không thể cập nhật hồ sơ. Vui lòng thử lại."));
    }
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-4" noValidate>
      <div className="flex flex-col items-center gap-2">
        <UserAvatar type="profile" name={displayName || profile.displayName} avatarUrl={previewUrl} />
        <p className="text-xs text-muted-foreground">Xem trước ảnh đại diện</p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="profile-displayName">Tên hiển thị<RequiredMark /></Label>
        <Input id="profile-displayName" maxLength={DISPLAY_NAME_MAX_LENGTH + 20} autoComplete="name" aria-required="true" aria-invalid={!!errors.displayName} {...register("displayName")} />
        {errors.displayName && <p className="error-message">{errors.displayName.message}</p>}
      </div>

      <div className="space-y-2">
        <Label htmlFor="profile-avatarUrl">Đường dẫn ảnh đại diện</Label>
        <Input id="profile-avatarUrl" type="url" inputMode="url" placeholder="https://..." autoComplete="off" aria-invalid={!!errors.avatarUrl} {...register("avatarUrl")} />
        {errors.avatarUrl ? (
          <p className="error-message">{errors.avatarUrl.message}</p>
        ) : (
          <p className="text-xs text-muted-foreground">Dán link ảnh https. Để trống để dùng chữ cái đầu của tên.</p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="profile-phone">Số điện thoại</Label>
        <Input id="profile-phone" type="tel" placeholder="+84 912 345 678" autoComplete="tel" aria-invalid={!!errors.phone} {...register("phone")} />
        {errors.phone && <p className="error-message">{errors.phone.message}</p>}
        <p className="text-xs text-muted-foreground">Chỉ bạn bè mới nhìn thấy số điện thoại và email của bạn.</p>
      </div>

      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <Label htmlFor="profile-bio">Giới thiệu</Label>
          <span className="text-xs tabular-nums text-muted-foreground">{bio.length}/{BIO_MAX_LENGTH}</span>
        </div>
        <Textarea id="profile-bio" rows={4} className="resize-none" aria-invalid={!!errors.bio} {...register("bio")} />
        {errors.bio && <p className="error-message">{errors.bio.message}</p>}
      </div>

      <div className="flex gap-2">
        <Button type="button" variant="outline" className="flex-1" onClick={onCancel} disabled={isSubmitting}>
          Hủy
        </Button>
        <Button type="submit" className="flex-1 bg-gradient-chat text-white hover:opacity-90" disabled={isSubmitting}>
          {isSubmitting ? <Loader2 className="animate-spin" /> : null} Lưu thay đổi
        </Button>
      </div>
    </form>
  );
};

export default ProfileEditForm;
